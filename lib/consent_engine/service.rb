# frozen_string_literal: true

require "securerandom"

module ConsentEngine
  # Application service that orchestrates commands against the event store and
  # answers decision queries. It contains NO authorization rules — those live
  # in Authorizer. This layer only validates payload shape, appends events, and
  # produces the authorization decision.
  class Service
    class ValidationError < StandardError; end

    attr_reader :store

    def initialize(store:, emergency_config: nil)
      @store            = store
      @emergency_config = emergency_config
    end

    # --- registration ---

    def register_person(person_id)
      @store.append(
        event_id: "PERSON-#{person_id}",
        type: "PERSON_REGISTERED",
        payload: { "personId" => person_id }
      )
    end

    def register_supporter(supporter_id)
      @store.append(
        event_id: "SUPPORTER-#{supporter_id}",
        type: "SUPPORTER_REGISTERED",
        payload: { "supporterId" => supporter_id }
      )
    end

    # --- consent ---

    def grant_consent(consent_id:, person_id:, supporter_id:, scopes:, from:, to: nil, witness_id: nil, emergency_minutes: nil, effective_at: nil)
      validate_id!(consent_id)
      validate_presence!(person_id, "person_id")
      validate_presence!(supporter_id, "supporter_id")
      validate_scopes!(scopes)
      validate_time!(from, "from")
      validate_time!(to, "to") if to

      @store.append(
        event_id: consent_id,
        type: "CONSENT_GRANTED",
        effective_at: effective_at || from,
        payload: {
          "personId"        => person_id,
          "supporterId"     => supporter_id,
          "scopes"          => scopes,
          "from"            => Time.iso8601(from.to_s).utc.iso8601,
          "to"              => to ? Time.iso8601(to.to_s).utc.iso8601 : nil,
          "witnessId"       => witness_id,
          "emergencyMinutes" => emergency_minutes
        }
      )
    end

    def revoke_consent(revocation_id:, consent_id:, at:, effective_at: nil)
      validate_id!(consent_id)
      validate_time!(at, "at")

      effective = effective_at ? Time.iso8601(effective_at.to_s) : Time.iso8601(at.to_s)
      # Determine whether this revocation arrives after an earlier one was
      # already recorded. The event is still appended (history is append-only)
      # but carries an +outOfOrder+ flag so auditors can see it did not
      # change the effective revocation time.
      prior = prior_revocations(consent_id)
      out_of_order = prior.any? { |r| r.effective_at < effective }

      @store.append(
        event_id: revocation_id,
        type: "CONSENT_REVOKED",
        effective_at: effective,
        payload: {
          "consentId"  => consent_id,
          "at"         => Time.iso8601(at.to_s).utc.iso8601,
          "outOfOrder" => out_of_order
        }
      )
    end

    # --- delegation ---

    def delegate(delegation_id:, source_consent_id:, from_supporter_id:, to_supporter_id:, scopes:, to: nil, emergency_minutes: nil, effective_at: nil)
      validate_id!(source_consent_id)
      validate_scopes!(scopes)

      source = @store.find_event(source_consent_id)
      raise ValidationError, "source consent #{source_consent_id} not found" unless source
      unless source.type == "CONSENT_GRANTED"
        raise ValidationError, "source event #{source_consent_id} is not a consent grant"
      end

      @store.append(
        event_id: delegation_id,
        type: "DELEGATION_GRANTED",
        effective_at: effective_at,
        payload: {
          "sourceConsentId"  => source_consent_id,
          "fromSupporterId"  => from_supporter_id,
          "toSupporterId"    => to_supporter_id,
          "scopes"           => scopes,
          "to"               => to ? Time.iso8601(to.to_s).utc.iso8601 : nil,
          "emergencyMinutes" => emergency_minutes
        }
      )
    end

    # --- emergency ---

    def activate_emergency(event_id:, person_id:, supporter_id: nil, effective_at: nil)
      @store.append(
        event_id: event_id,
        type: "EMERGENCY_ACTIVATED",
        effective_at: effective_at,
        payload: {
          "personId"   => person_id,
          "supporterId" => supporter_id
        }
      )
    end

    def record_emergency_review(event_id:, person_id:, effective_at: nil)
      @store.append(
        event_id: event_id,
        type: "EMERGENCY_REVIEWED",
        effective_at: effective_at,
        payload: { "personId" => person_id }
      )
    end

    # --- decision ---

    # Evaluate at +as_of+ (business time). If +as_of+ is nil the current
    # wall-clock time is used. The snapshot is pinned to the high seq at the
    # moment of the call, so later writes cannot change this answer.
    #
    # If +idempotency_key+ is provided and a decision with the same key was
    # already recorded, the prior decision is returned unchanged and NO new
    # event is appended. This prevents duplicate submissions from expanding
    # scope or resetting any budget.
    def decide(person_id:, supporter_id:, scope:, as_of: nil, seen_seq: nil, idempotency_key: nil)
      # Idempotency: if this exact key has already been used, replay the
      # recorded decision rather than re-evaluating. This guarantees that
      # retries cannot change scope, budget, or chain.
      if idempotency_key
        prior = find_decision_by_idempotency_key(idempotency_key)
        return replay(prior.event_id) if prior
      end

      decision_time = as_of ? Time.iso8601(as_of.to_s) : @store.clock.call
      seq = seen_seq || @store.high_seq
      events = @store.snapshot(seen_seq: seq)

      decision = Authorizer.decide(
        events: events,
        person_id: person_id,
        supporter_id: supporter_id,
        scope: scope,
        decision_at: decision_time,
        seen_seq: seq,
        emergency_config: @emergency_config
      )

      record_decision(person_id, decision, idempotency_key)
      decision
    end

    # Replay a previously-recorded decision at its exact (decision_at, seen_seq).
    # MUST return an identical reason_code and chain.
    def replay(decision_event_id)
      ev = @store.find_event(decision_event_id)
      raise ValidationError, "decision #{decision_event_id} not found" unless ev
      raise ValidationError, "event is not a decision" unless ev.type == "DECISION_RECORDED"

      p = ev.payload
      decision_at = Time.iso8601(p["decisionAt"])
      seq         = p["seenSeq"]

      Authorizer.decide(
        events: @store.snapshot(seen_seq: seq),
        person_id: p["personId"],
        supporter_id: p["supporterId"],
        scope: p["scope"],
        decision_at: decision_at,
        seen_seq: seq,
        emergency_config: @emergency_config
      )
    end

    def events
      @store.all
    end

    def find_decision_by_idempotency_key(key)
      @store.all.find do |e|
        e.type == "DECISION_RECORDED" && e.payload["idempotencyKey"] == key
      end
    end

    private

    def record_decision(person_id, decision, idempotency_key = nil)
      id = idempotency_key || "DECISION-#{decision.seen_seq}-#{decision.decision_at.to_i}-#{SecureRandom.hex(4)}"
      @store.append(
        event_id: id,
        type: "DECISION_RECORDED",
        effective_at: decision.decision_at,
        payload: {
          "personId"       => person_id,
          "supporterId"    => decision.subject_id,
          "scope"          => decision.scope,
          "decisionAt"     => decision.decision_at.utc.iso8601,
          "seenSeq"        => decision.seen_seq,
          "granted"        => decision.granted?,
          "reasonCode"     => decision.reason_code,
          "idempotencyKey" => idempotency_key
        }
      )
    end

    def prior_revocations(consent_id)
      @store.all.select do |e|
        e.type == "CONSENT_REVOKED" && e.payload["consentId"] == consent_id
      end
    end

    def extract_person_id(decision)
      link = decision.chain.first
      return nil unless link
      link.from_id
    end

    def validate_id!(id)
      raise ValidationError, "id is required" if id.nil? || id.to_s.empty?
    end

    def validate_presence!(v, name)
      raise ValidationError, "#{name} is required" if v.nil? || v.to_s.empty?
    end

    def validate_scopes!(scopes)
      raise ValidationError, "scopes must be a non-empty array" unless scopes.is_a?(Array) && !scopes.empty?
    end

    def validate_time!(t, name)
      Time.iso8601(t.to_s)
    rescue ArgumentError
      raise ValidationError, "#{name} must be ISO8601"
    end
  end
end
