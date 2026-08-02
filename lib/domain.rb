# frozen_string_literal: true

require "time"

# Pure Ruby domain objects for the supported-decision consent engine.
# This module has NO dependency on HTTP routes or persistence. Every
# authorization verdict is a pure function of:
#   - the immutable fact snapshot (World) visible at a fixed audit sequence
#   - the fixed event time of the decision
# Replaying with the same (sequence, event time) always yields the same
# reason code and authorization chain.
module Domain
  module Reason
    OK_DIRECT                    = "OK_DIRECT"
    OK_DELEGATED                 = "OK_DELEGATED"
    OK_EMERGENCY                 = "OK_EMERGENCY"
    OK_EMERGENCY_REVIEW_PENDING  = "OK_EMERGENCY_REVIEW_PENDING"
    DENY_NO_CONSENT              = "DENY_NO_CONSENT"               # silence is not consent
    DENY_SCOPE_NOT_COVERED       = "DENY_SCOPE_NOT_COVERED"        # missing scope is not consent
    DENY_CONSENT_EXPIRED         = "DENY_CONSENT_EXPIRED"          # expired is not consent
    DENY_CONSENT_REVOKED         = "DENY_CONSENT_REVOKED"          # revoked is not consent
    DENY_DELEGATION_CYCLE        = "DENY_DELEGATION_CYCLE"
    DENY_DELEGATION_SCOPE        = "DENY_DELEGATION_SCOPE"         # broader than source
    DENY_DELEGATION_EXPIRED      = "DENY_DELEGATION_EXPIRED"
    DENY_DELEGATION_SOURCE_EXPIRED = "DENY_DELEGATION_SOURCE_EXPIRED"
    DENY_DELEGATION_SOURCE_REVOKED = "DENY_DELEGATION_SOURCE_REVOKED"
    DENY_EMERGENCY_TIMEOUT       = "DENY_EMERGENCY_TIMEOUT"
  end

  # Deterministic denial precedence. When several independent facts each
  # justify a denial, the first matching entry wins, so the reason code is
  # stable across runs and replays.
  DENIAL_PRECEDENCE = [
    Reason::DENY_DELEGATION_CYCLE,
    Reason::DENY_DELEGATION_SOURCE_REVOKED,
    Reason::DENY_DELEGATION_SOURCE_EXPIRED,
    Reason::DENY_DELEGATION_EXPIRED,
    Reason::DENY_DELEGATION_SCOPE,
    Reason::DENY_CONSENT_REVOKED,
    Reason::DENY_CONSENT_EXPIRED,
    Reason::DENY_SCOPE_NOT_COVERED,
    Reason::DENY_EMERGENCY_TIMEOUT,
    Reason::DENY_NO_CONSENT
  ].freeze

  Consent = Struct.new(:id, :person_id, :supporter_id, :scopes, :valid_from, :valid_to, :witness_id, keyword_init: true) do
    # Half-open window [from, to): a consent is active at `from`, expired at `to`.
    def active_at?(t) = valid_from <= t && t < valid_to
    def covers?(scope) = scopes.include?(scope)
  end

  Delegation = Struct.new(:id, :source_consent_id, :from_supporter_id, :to_supporter_id,
                          :scopes, :effective_from, :valid_to, :created_seq, keyword_init: true) do
    def active_at?(t) = effective_from <= t && (valid_to.nil? || t < valid_to)
    def covers?(scope) = scopes.include?(scope)
  end

  Revocation = Struct.new(:id, :consent_id, :at, keyword_init: true)

  EmergencyEpisode = Struct.new(:id, :supporter_id, :scope, :started_at, :max_minutes, :reviewed_at, keyword_init: true) do
    def window_end = started_at + max_minutes * 60
    # Inclusive window: still authorized exactly at window_end, timed out after.
    def within_window?(t) = started_at <= t && t <= window_end
    def timed_out?(t) = t > window_end
    def reviewed? = !reviewed_at.nil?
  end

  EmergencyPolicy = Struct.new(:allowed_scope, :max_minutes, :requires_review_event, keyword_init: true)

  # Immutable fact snapshot: every fact visible at audit sequence <= as_of_seq.
  class World
    attr_reader :persons, :supporters, :consents, :delegations, :revocations,
                :emergencies, :emergency_policies, :as_of_seq

    def initialize(persons: [], supporters: [], consents: [], delegations: [],
                   revocations: [], emergencies: [], emergency_policies: {}, as_of_seq: 0)
      @persons = persons
      @supporters = supporters
      @consents = consents
      @delegations = delegations.sort_by(&:created_seq)
      @revocations = revocations # first revocation per consent wins
      @emergencies = emergencies
      @emergency_policies = emergency_policies # person_id => EmergencyPolicy
      @as_of_seq = as_of_seq
    end

    # Fail-closed tie-break: a revocation whose event time is exactly the
    # decision time has already taken effect (revoked_at <= t).
    def revoked?(consent_id, t)
      rev = @revocations.find { |r| r.consent_id == consent_id }
      !rev.nil? && rev.at <= t
    end

    def revocation_for(consent_id) = @revocations.find { |r| r.consent_id == consent_id }

    def consent_by_id(id) = @consents.find { |c| c.id == id }

    def consents_of(supporter_id) = @consents.select { |c| c.supporter_id == supporter_id }

    def emergencies_of(supporter_id) = @emergencies.select { |e| e.supporter_id == supporter_id }

    # Effective scopes a supporter may further delegate from `source_consent_id`,
    # i.e. the narrowest link along every delegation path leading to them.
    def effective_delegatable_scopes(source_consent_id, supporter_id)
      root = consent_by_id(source_consent_id)
      return [] if root.nil?

      paths = delegation_paths(supporter_id).select do |p|
        p[:root_consent] && p[:root_consent].id == source_consent_id && !p[:cycle]
      end
      return root.scopes if supporter_id == root.supporter_id
      return [] if paths.empty?

      paths.map { |p| (p[:delegations].map(&:scopes) + [root.scopes]).reduce(:&) }.max_by(&:size) || []
    end

    # All delegation chains from `supporter_id` upward toward a direct consent
    # holder. Each result: {delegations: [...], root_consent: Consent|nil,
    # cycle: bool}. Visited-set tracking makes cycles explicit and terminating.
    def delegation_paths(supporter_id)
      results = []
      walk = lambda do |current, chain, visited|
        incoming = @delegations.select { |d| d.to_supporter_id == current }
        if incoming.empty?
          results << { delegations: chain, root_consent: nil, cycle: false } unless chain.empty?
          next
        end
        incoming.each do |d|
          if visited.include?(d.from_supporter_id)
            results << { delegations: chain + [d], root_consent: nil, cycle: true }
            next
          end
          root = @consents.find { |c| c.id == d.source_consent_id && c.supporter_id == d.from_supporter_id }
          if root
            results << { delegations: chain + [d], root_consent: root, cycle: false }
          else
            walk.call(d.from_supporter_id, chain + [d], visited + [d.from_supporter_id])
          end
        end
      end
      walk.call(supporter_id, [], [supporter_id])
      results
    end

    # Would delegating from `from_supporter_id` to `to_supporter_id` close a
    # cycle? True when `from` is reachable from `to` through existing
    # delegations (or they are the same supporter).
    def delegation_would_cycle?(from_supporter_id, to_supporter_id)
      return true if from_supporter_id == to_supporter_id

      # Adding edge from->to closes a cycle iff `from` is already reachable
      # from `to` following existing from->to delegation edges.
      stack = [to_supporter_id]
      visited = {}
      until stack.empty?
        current = stack.pop
        return true if current == from_supporter_id
        next if visited[current]

        visited[current] = true
        @delegations.select { |d| d.from_supporter_id == current }.each do |d|
          stack << d.to_supporter_id
        end
      end
      false
    end
  end

  Decision = Struct.new(:reason_code, :authorized, :chain, keyword_init: true) do
    def authorized? = authorized
  end

  # The authorization engine. Pure: same World + same inputs => same Decision.
  class Authorizer
    class << self
      def evaluate(world:, supporter_id:, scope:, at:)
        denials = []

        direct = world.consents_of(supporter_id)
        direct_covering = direct.select { |c| c.covers?(scope) }

        ok = direct_covering.find { |c| c.active_at?(at) && !world.revoked?(c.id, at) }
        return Decision.new(reason_code: Reason::OK_DIRECT, authorized: true,
                            chain: [consent_link(ok, "active")]) if ok

        direct_covering.each do |c|
          if world.revoked?(c.id, at)
            denials << [Reason::DENY_CONSENT_REVOKED, [consent_link(c, "revoked", world.revocation_for(c.id))]]
          elsif !c.active_at?(at)
            denials << [Reason::DENY_CONSENT_EXPIRED, [consent_link(c, "expired")]]
          end
        end
        if direct_covering.empty? && !direct.empty?
          denials << [Reason::DENY_SCOPE_NOT_COVERED, direct.map { |c| consent_link(c, "scope_missing") }]
        end

        world.delegation_paths(supporter_id).each do |path|
          status = path_status(world, path, scope, at)
          if status == :ok
            return Decision.new(reason_code: Reason::OK_DELEGATED, authorized: true,
                                chain: path_chain(world, path, scope, at))
          end
          denials << [PATH_DENIAL.fetch(status), path_chain(world, path, scope, at)] if PATH_DENIAL.key?(status)
        end

        world.emergencies_of(supporter_id).select { |e| e.scope == scope }.each do |ep|
          if ep.within_window?(at)
            code = ep.reviewed? ? Reason::OK_EMERGENCY : Reason::OK_EMERGENCY_REVIEW_PENDING
            return Decision.new(reason_code: code, authorized: true, chain: [emergency_link(ep, at)])
          elsif ep.timed_out?(at)
            denials << [Reason::DENY_EMERGENCY_TIMEOUT, [emergency_link(ep, at)]]
          end
        end

        denials << [Reason::DENY_NO_CONSENT, []] if denials.empty?
        reason, chain = denials.min_by { |r, _| DENIAL_PRECEDENCE.index(r) }
        Decision.new(reason_code: reason, authorized: false, chain: chain)
      end

      PATH_DENIAL = {
        cycle: Reason::DENY_DELEGATION_CYCLE,
        source_revoked: Reason::DENY_DELEGATION_SOURCE_REVOKED,
        source_expired: Reason::DENY_DELEGATION_SOURCE_EXPIRED,
        delegation_expired: Reason::DENY_DELEGATION_EXPIRED,
        scope_missing: Reason::DENY_DELEGATION_SCOPE
      }.freeze

      def path_status(world, path, scope, at)
        return :cycle if path[:cycle]
        return :dead_end if path[:root_consent].nil?

        links = path[:delegations]
        root = path[:root_consent]
        return :scope_missing unless root.covers?(scope) && links.all? { |d| d.covers?(scope) }
        return :source_revoked if world.revoked?(root.id, at)
        return :source_expired unless root.active_at?(at)
        return :delegation_expired unless links.all? { |d| d.active_at?(at) }

        :ok
      end

      def path_chain(world, path, scope, at)
        entries = []
        if path[:root_consent]
          root = path[:root_consent]
          status = if !root.covers?(scope)
                     "scope_missing"
                   elsif world.revoked?(root.id, at)
                     "revoked"
                   elsif !root.active_at?(at)
                     "expired"
                   else
                     "active"
                   end
          entries << consent_link(root, status, world.revocation_for(root.id))
        end
        path[:delegations].reverse_each do |d|
          status = if path[:cycle]
                     "cycle"
                   elsif !d.covers?(scope)
                     "scope_missing"
                   elsif !d.active_at?(at)
                     "expired"
                   else
                     "active"
                   end
          entries << delegation_link(d, status)
        end
        entries
      end

      def consent_link(c, status, revocation = nil)
        h = {
          "type" => "consent", "id" => c.id, "personId" => c.person_id,
          "supporterId" => c.supporter_id, "scopes" => c.scopes,
          "from" => c.valid_from.utc.iso8601, "to" => c.valid_to.utc.iso8601,
          "witnessId" => c.witness_id, "status" => status
        }
        h["revokedAt"] = revocation.at.utc.iso8601 if revocation
        h
      end

      def delegation_link(d, status)
        {
          "type" => "delegation", "id" => d.id,
          "sourceConsentId" => d.source_consent_id,
          "fromSupporterId" => d.from_supporter_id, "toSupporterId" => d.to_supporter_id,
          "scopes" => d.scopes,
          "effectiveFrom" => d.effective_from.utc.iso8601,
          "to" => d.valid_to&.utc&.iso8601,
          "createdSeq" => d.created_seq, "status" => status
        }
      end

      def emergency_link(ep, at)
        {
          "type" => "emergency", "id" => ep.id, "supporterId" => ep.supporter_id,
          "scope" => ep.scope,
          "startedAt" => ep.started_at.utc.iso8601,
          "windowEnd" => ep.window_end.utc.iso8601,
          "reviewedAt" => ep.reviewed_at&.utc&.iso8601,
          "status" => ep.within_window?(at) ? (ep.reviewed? ? "within_window_reviewed" : "within_window_review_pending") : "timeout"
        }
      end
    end
  end

  # Write-time validation for new facts. Returns nil when valid, otherwise a
  # stable error code. Pure functions of the World snapshot, same as evaluate.
  module Validate
    module_function

    def consent(world:, person_id:, supporter_id:, scopes:, valid_from:, valid_to:, witness_id:)
      return "PERSON_UNKNOWN" unless world.persons.include?(person_id)
      return "SUPPORTER_UNKNOWN" unless world.supporters.include?(supporter_id)
      return "SCOPES_EMPTY" if scopes.nil? || scopes.empty?
      return "WITNESS_REQUIRED" if witness_id.nil? || witness_id.to_s.strip.empty?
      return "WINDOW_INVALID" unless valid_from < valid_to

      nil
    end

    def delegation(world:, source_consent_id:, from_supporter_id:, to_supporter_id:, scopes:, effective_from:, valid_to:)
      root = world.consent_by_id(source_consent_id)
      return "SOURCE_CONSENT_UNKNOWN" if root.nil?
      return "SUPPORTER_UNKNOWN" unless world.supporters.include?(to_supporter_id)
      return "SCOPES_EMPTY" if scopes.nil? || scopes.empty?
      return "DELEGATION_CYCLE" if world.delegation_would_cycle?(from_supporter_id, to_supporter_id)

      # The delegator must actually hold (directly or by delegation) every
      # scope they pass on: a delegation broader than its source never grants.
      allowed = world.effective_delegatable_scopes(source_consent_id, from_supporter_id)
      return "DELEGATION_NOT_HELD_BY_SENDER" if allowed.empty?
      return "DELEGATION_BROADER_THAN_SOURCE" unless (scopes - allowed).empty?

      # Delegation after source expiry/revocation is rejected at write time.
      return "DELEGATION_SOURCE_REVOKED" if world.revoked?(root.id, effective_from)
      return "DELEGATION_SOURCE_EXPIRED" unless root.active_at?(effective_from)
      return "DELEGATION_WINDOW_INVALID" if valid_to && (valid_to <= effective_from || valid_to > root.valid_to)

      nil
    end

    def revocation(world:, consent_id:)
      return "CONSENT_UNKNOWN" if world.consent_by_id(consent_id).nil?
      return "ALREADY_REVOKED" if world.revocation_for(consent_id)

      nil
    end

    def emergency_start(world:, person_id:, supporter_id:, scope:)
      policy = world.emergency_policies[person_id]
      return "EMERGENCY_POLICY_MISSING" if policy.nil?
      return "SUPPORTER_UNKNOWN" unless world.supporters.include?(supporter_id)
      return "EMERGENCY_SCOPE_NOT_ALLOWED" unless scope == policy.allowed_scope

      nil
    end
  end
end
