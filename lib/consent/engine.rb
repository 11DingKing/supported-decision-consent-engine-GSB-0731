# frozen_string_literal: true

require_relative "reason_codes"
require_relative "projection"
require_relative "instant"

module Consent
  # The Engine is the ONLY place authority is judged. It is a pure function of
  # (recorded facts, as-of event_time, as-of audit seq). HTTP routing and the
  # SQLite store never decide authorization; they only supply facts and anchors.
  #
  # Determinism guarantees:
  #   * Every decision fixes an event_time and an as_of_seq.
  #   * The projection hides any event with seq > as_of_seq.
  #   * Denial selection uses a fixed precedence, never evaluation-time state.
  # Therefore replaying a decision reproduces the identical reason code and
  # authority chain, and no concurrent append can widen scope or rewrite a past
  # decision.
  #
  # Conservative default: silence is never authority. Missing, unwitnessed,
  # not-yet-effective, expired, revoked, or broader-than-source consent all
  # deny ordinary authority.
  class Engine
    Outcome = Struct.new(:code, :chain, keyword_init: true) do
      def authorized?
        ReasonCodes.authorized?(code)
      end
    end

    Decision = Struct.new(
      :authorized, :reason_code, :authority_chain,
      :supporter_id, :scope, :event_time, :as_of_seq,
      keyword_init: true
    ) do
      def to_h
        {
          "authorized" => authorized,
          "reasonCode" => reason_code,
          "supporterId" => supporter_id,
          "scope" => scope,
          "eventTime" => event_time&.iso8601,
          "asOfSeq" => as_of_seq,
          "authorityChain" => authority_chain
        }
      end
    end

    def initialize(projection)
      @projection = projection
    end

    # Top-level evaluation. Tries ordinary authority (direct consent then
    # delegation, recursively), and only if that fails considers an emergency
    # exception. Returns a Decision anchored to (event_time, as_of_seq).
    def evaluate(supporter_id:, scope:, at:)
      at = Instant.parse(at)
      candidates = []

      candidates << Outcome.new(code: ReasonCodes::UNKNOWN_SCOPE, chain: []) unless @projection.scope?(scope)
      candidates << Outcome.new(code: ReasonCodes::UNKNOWN_SUPPORTER, chain: []) unless @projection.supporter?(supporter_id)

      if @projection.scope?(scope) && @projection.supporter?(supporter_id)
        ordinary = authority_for(supporter_id, scope, at, [supporter_id])
        candidates.concat(ordinary)
      end

      winner = pick_authorized(candidates)
      winner ||= emergency_outcome(supporter_id, scope, at, candidates)
      winner ||= denial_outcome(candidates)

      Decision.new(
        authorized: winner.authorized?,
        reason_code: winner.code,
        authority_chain: winner.chain,
        supporter_id: supporter_id,
        scope: scope,
        event_time: at,
        as_of_seq: @projection.as_of_seq
      )
    end

    private

    # Resolve ordinary (consent + delegation) authority for a supporter/scope.
    # Returns a list of candidate Outcomes (authorized and/or denials). visited
    # holds the supporters already on the resolution path for cycle detection.
    def authority_for(supporter_id, scope, at, visited)
      candidates = []

      scoped_consents = @projection.consents.values.select do |c|
        c.supporter_id == supporter_id && c.scopes.include?(scope)
      end
      any_consents = @projection.consents.values.any? { |c| c.supporter_id == supporter_id }

      scoped_consents.sort_by(&:granted_seq).each do |c|
        code = consent_validity(c, at)
        candidates << if code == :ok
          Outcome.new(code: ReasonCodes::AUTHORIZED_DIRECT_CONSENT, chain: [consent_link(c)])
        else
          Outcome.new(code: code, chain: [])
        end
      end

      scoped_delegations = @projection.delegations.values.select do |d|
        d.to_supporter_id == supporter_id && d.scopes.include?(scope)
      end
      any_delegations = @projection.delegations.values.any? { |d| d.to_supporter_id == supporter_id }

      scoped_delegations.sort_by(&:created_seq).each do |d|
        candidates.concat(evaluate_delegation(d, scope, at, visited))
      end

      if candidates.empty?
        # No consent and no delegation names this scope for this supporter.
        candidates << if any_consents || any_delegations
          Outcome.new(code: ReasonCodes::SCOPE_NOT_IN_CONSENT, chain: [])
        else
          Outcome.new(code: ReasonCodes::NO_CONSENT, chain: [])
        end
      end

      candidates
    end

    # Validate a delegation link and its source authority as-of `at`.
    def evaluate_delegation(deleg, scope, at, visited)
      from = deleg.from_supporter_id

      # Cycle: the source supporter is already on our resolution path.
      return [Outcome.new(code: ReasonCodes::DELEGATION_CYCLE, chain: [])] if visited.include?(from)

      results = []
      del_code = delegation_validity(deleg, at)
      source_candidates = authority_for(from, scope, at, visited + [from])
      source_ok = source_candidates.find(&:authorized?)

      if source_ok
        results << if del_code == :ok
          Outcome.new(
            code: ReasonCodes::AUTHORIZED_DELEGATED_CONSENT,
            chain: source_ok.chain + [delegation_link(deleg)]
          )
        else
          # Source is fine but this delegation link is itself invalid.
          Outcome.new(code: del_code, chain: [])
        end
      else
        # Source authority is absent. Translate the upstream failure into a
        # delegation-boundary reason so the caller learns WHY the chain broke.
        src_code = ReasonCodes.most_specific_denial(source_candidates.map(&:code))
        results << Outcome.new(code: translate_source_failure(src_code), chain: [])
        # Also surface a broken delegation link if it independently failed, so
        # precedence can pick the most specific overall.
        results << Outcome.new(code: del_code, chain: []) unless del_code == :ok
      end

      results
    end

    # A source failure, seen from the delegation boundary. A source that never
    # held the scope means the delegation claimed more than its source
    # (scope exceeds source); a source that expired/was revoked means the
    # source authority is invalid; an upstream cycle propagates as a cycle.
    def translate_source_failure(code)
      case code
      when ReasonCodes::SCOPE_NOT_IN_CONSENT, ReasonCodes::NO_CONSENT
        ReasonCodes::DELEGATION_SCOPE_EXCEEDS_SOURCE
      when ReasonCodes::DELEGATION_CYCLE
        ReasonCodes::DELEGATION_CYCLE
      when ReasonCodes::CONSENT_EXPIRED, ReasonCodes::CONSENT_REVOKED,
           ReasonCodes::CONSENT_NOT_YET_EFFECTIVE, ReasonCodes::CONSENT_NOT_WITNESSED,
           ReasonCodes::SOURCE_CONSENT_INVALID, ReasonCodes::DELEGATION_EXPIRED,
           ReasonCodes::DELEGATION_REVOKED, ReasonCodes::DELEGATION_NOT_YET_EFFECTIVE,
           ReasonCodes::DELEGATION_SCOPE_EXCEEDS_SOURCE
        ReasonCodes::SOURCE_CONSENT_INVALID
      else
        ReasonCodes::DELEGATION_SOURCE_AUTHORITY_MISSING
      end
    end

    # Consent temporal/witness validity at `at`. Revocation is checked before
    # expiry so a decision at the exact revocation instant is deterministically
    # "revoked" (t >= revoked_at). Window is [from, to).
    def consent_validity(consent, at)
      return ReasonCodes::CONSENT_NOT_WITNESSED if blank?(consent.witness_id)
      return ReasonCodes::CONSENT_REVOKED if at.at_or_after?(consent.revoked_at)
      return ReasonCodes::CONSENT_NOT_YET_EFFECTIVE if consent.from && at < consent.from
      return ReasonCodes::CONSENT_EXPIRED if consent.to && at >= consent.to

      :ok
    end

    def delegation_validity(deleg, at)
      return ReasonCodes::DELEGATION_REVOKED if at.at_or_after?(deleg.revoked_at)
      return ReasonCodes::DELEGATION_NOT_YET_EFFECTIVE if deleg.from && at < deleg.from
      return ReasonCodes::DELEGATION_EXPIRED if deleg.to && at >= deleg.to

      :ok
    end

    # Emergency exception: a narrow, time-boxed fallback. It is never
    # delegatable and is only considered when ordinary authority failed.
    def emergency_outcome(supporter_id, scope, at, ordinary_candidates)
      policy = @projection.emergency_policy
      relevant = @projection.emergencies.values.select do |e|
        e.supporter_id == supporter_id && e.scope == scope
      end
      return nil if relevant.empty?

      relevant.sort_by(&:created_seq).each do |e|
        code = emergency_validity(e, policy, at)
        if code == :ok
          return Outcome.new(code: ReasonCodes::AUTHORIZED_EMERGENCY, chain: [emergency_link(e)])
        end

        ordinary_candidates << Outcome.new(code: code, chain: [])
      end
      nil
    end

    def emergency_validity(emergency, policy, at)
      allowed_scope = policy&.allowed_scope
      max_minutes = emergency.max_minutes || policy&.max_minutes
      requires_review = policy.nil? ? false : policy.requires_review_event

      return ReasonCodes::EMERGENCY_SCOPE_NOT_ALLOWED if allowed_scope && emergency.scope != allowed_scope
      return ReasonCodes::EMERGENCY_SCOPE_NOT_ALLOWED if allowed_scope.nil?

      if max_minutes
        deadline = Instant.new(emergency.invoked_at.time + (max_minutes * 60))
        return ReasonCodes::EMERGENCY_EXPIRED if at >= deadline
      end
      return ReasonCodes::EMERGENCY_NOT_YET_EFFECTIVE if at < emergency.invoked_at

      # Silence about review is not authority: a required review must be on
      # record (as-of seq) for the exception to hold.
      return ReasonCodes::EMERGENCY_REVIEW_MISSING if requires_review && emergency.reviewed_at.nil?

      :ok
    end

    # Deterministic winner among authorized candidates: prefer a direct
    # consent, otherwise the delegated path with the shortest chain, tie-broken
    # by a stable serialization of the chain.
    def pick_authorized(candidates)
      authorized = candidates.select(&:authorized?)
      return nil if authorized.empty?

      direct = authorized.find { |o| o.code == ReasonCodes::AUTHORIZED_DIRECT_CONSENT }
      return direct if direct

      authorized.min_by { |o| [o.chain.length, o.chain.to_s] }
    end

    def denial_outcome(candidates)
      code = ReasonCodes.most_specific_denial(candidates.map(&:code))
      Outcome.new(code: code, chain: [])
    end

    def consent_link(consent)
      {
        "type" => "consent",
        "consentId" => consent.id,
        "supporterId" => consent.supporter_id,
        "scopes" => consent.scopes,
        "from" => consent.from&.iso8601,
        "to" => consent.to&.iso8601,
        "witnessId" => consent.witness_id
      }
    end

    def delegation_link(deleg)
      {
        "type" => "delegation",
        "delegationId" => deleg.id,
        "sourceConsentId" => deleg.source_consent_id,
        "fromSupporterId" => deleg.from_supporter_id,
        "toSupporterId" => deleg.to_supporter_id,
        "scopes" => deleg.scopes
      }
    end

    def emergency_link(emergency)
      {
        "type" => "emergency",
        "emergencyId" => emergency.id,
        "supporterId" => emergency.supporter_id,
        "scope" => emergency.scope,
        "invokedAt" => emergency.invoked_at&.iso8601,
        "maxMinutes" => emergency.max_minutes
      }
    end

    def blank?(value)
      value.nil? || (value.respond_to?(:empty?) && value.empty?)
    end
  end
end
