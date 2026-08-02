# frozen_string_literal: true

require_relative "event_store"
require_relative "projection"
require_relative "engine"
require_relative "instant"

module Consent
  # Ledger is the application-facing coordinator. It records facts (validating
  # only structural well-formedness, never authority) and answers decisions by
  # projecting the log and delegating the judgement to the pure Engine.
  #
  # Every decision is pinned to (event_time, as_of_seq); the same pair replays
  # to the same reason code and authority chain. Recording a decision does not
  # change state, so audit is a faithful, append-only trail.
  class Ledger
    class ValidationError < StandardError; end

    def initialize(store)
      @store = store
    end

    # --- Fact recording -----------------------------------------------------

    def register_person(person_id, event_time: nil)
      require_present!(person_id, "personId")
      append("PERSON_REGISTERED", { "personId" => person_id }, event_time)
    end

    def add_supporter(supporter_id, event_time: nil)
      require_present!(supporter_id, "supporterId")
      append("SUPPORTER_ADDED", { "supporterId" => supporter_id }, event_time)
    end

    def define_scope(scope, event_time: nil)
      require_present!(scope, "scope")
      append("SCOPE_DEFINED", { "scope" => scope }, event_time)
    end

    def grant_consent(id:, supporter_id:, scopes:, from:, to:, witness_id:, emergency_budget_minutes: nil, event_time: nil)
      require_present!(id, "id")
      require_present!(supporter_id, "supporterId")
      raise ValidationError, "scopes must be a non-empty array" if !scopes.is_a?(Array) || scopes.empty?

      payload = {
        "id" => id,
        "supporterId" => supporter_id,
        "scopes" => scopes,
        "from" => normalize_time(from),
        "to" => normalize_time(to),
        "witnessId" => witness_id,
        "emergencyBudgetMinutes" => emergency_budget_minutes
      }
      append("CONSENT_GRANTED", payload, event_time || from)
    end

    def revoke_consent(consent_id:, at:, event_time: nil)
      require_present!(consent_id, "consentId")
      require_present!(at, "at")
      append("CONSENT_REVOKED", { "consentId" => consent_id, "at" => normalize_time(at) }, event_time || at)
    end

    def create_delegation(id:, source_consent_id:, from_supporter_id:, to_supporter_id:, scopes:, from: nil, to: nil, budget_minutes: nil, event_time: nil)
      require_present!(id, "id")
      require_present!(source_consent_id, "sourceConsentId")
      require_present!(from_supporter_id, "fromSupporterId")
      require_present!(to_supporter_id, "toSupporterId")
      raise ValidationError, "scopes must be a non-empty array" if !scopes.is_a?(Array) || scopes.empty?

      payload = {
        "id" => id,
        "sourceConsentId" => source_consent_id,
        "fromSupporterId" => from_supporter_id,
        "toSupporterId" => to_supporter_id,
        "scopes" => scopes,
        "from" => normalize_time(from),
        "to" => normalize_time(to),
        "budgetMinutes" => budget_minutes
      }
      append("DELEGATION_CREATED", payload, event_time || from)
    end

    def revoke_delegation(delegation_id:, at:, event_time: nil)
      require_present!(delegation_id, "delegationId")
      require_present!(at, "at")
      append("DELEGATION_REVOKED", { "delegationId" => delegation_id, "at" => normalize_time(at) }, event_time || at)
    end

    def set_emergency_policy(allowed_scope:, max_minutes:, requires_review_event:, event_time: nil)
      require_present!(allowed_scope, "allowedScope")
      payload = {
        "allowedScope" => allowed_scope,
        "maxMinutes" => max_minutes,
        "requiresReviewEvent" => requires_review_event
      }
      append("EMERGENCY_POLICY_SET", payload, event_time)
    end

    def invoke_emergency(id:, supporter_id:, scope:, at:, max_minutes: nil, event_time: nil)
      require_present!(id, "id")
      require_present!(supporter_id, "supporterId")
      require_present!(scope, "scope")
      require_present!(at, "at")
      payload = {
        "id" => id,
        "supporterId" => supporter_id,
        "scope" => scope,
        "at" => normalize_time(at),
        "maxMinutes" => max_minutes
      }
      append("EMERGENCY_INVOKED", payload, event_time || at)
    end

    def review_emergency(emergency_id:, at:, event_time: nil)
      require_present!(emergency_id, "emergencyId")
      require_present!(at, "at")
      append("EMERGENCY_REVIEWED", { "emergencyId" => emergency_id, "at" => normalize_time(at) }, event_time || at)
    end

    # Record consumption of emergency-exception minutes. Idempotent by
    # consumptionId: resubmitting the same consumption records the fact once, so
    # a duplicate can never drain (or reset) the budget twice.
    def consume_emergency(emergency_id:, consumption_id:, minutes:, at:, event_time: nil)
      require_present!(emergency_id, "emergencyId")
      require_present!(consumption_id, "consumptionId")
      require_present!(at, "at")
      raise ValidationError, "minutes must be a positive integer" unless minutes.is_a?(Integer) && minutes.positive?

      payload = {
        "emergencyId" => emergency_id,
        "consumptionId" => consumption_id,
        "minutes" => minutes,
        "at" => normalize_time(at)
      }
      append("EMERGENCY_CONSUMED", payload, event_time || at, request_id: "consume:#{consumption_id}")
    end

    # Revoke an emergency exception at an instant. Monotonic and non-destructive:
    # it stops further authority from `at` but never erases minutes already
    # consumed before it.
    def revoke_emergency(emergency_id:, at:, event_time: nil)
      require_present!(emergency_id, "emergencyId")
      require_present!(at, "at")
      append("EMERGENCY_REVOKED", { "emergencyId" => emergency_id, "at" => normalize_time(at) }, event_time || at)
    end

    # --- Decisions ----------------------------------------------------------

    # Evaluate authority and record the decision as an immutable audit event.
    # The decision is anchored to (event_time, as_of_seq); as_of_seq defaults
    # to the current audit tip captured atomically before evaluation.
    #
    # When `request_id` is supplied the recording is IDEMPOTENT: a resubmitted
    # decision reproduces the original outcome — same reason code, same
    # authority chain, and the SAME as_of_seq boundary that was pinned the first
    # time — without appending a second audit fact. A duplicate submission can
    # therefore never widen scope, reset a budget, or shift the audit boundary.
    def decide(supporter_id:, scope:, at:, as_of_seq: nil, record: true, request_id: nil)
      at_norm = normalize_time(at)

      if record && request_id && (prior = @store.event_for_request("decision:#{request_id}"))
        return decision_from_event(prior)
      end

      seq_ceiling = as_of_seq || @store.max_seq
      decision = evaluate(supporter_id: supporter_id, scope: scope, at: at_norm, as_of_seq: seq_ceiling)

      if record
        append(
          "DECISION_REQUESTED",
          {
            "supporterId" => supporter_id,
            "scope" => scope,
            "at" => at_norm,
            "asOfSeq" => seq_ceiling,
            "authorized" => decision.authorized,
            "reasonCode" => decision.reason_code,
            "authorityChain" => decision.authority_chain
          },
          at_norm,
          request_id: request_id && "decision:#{request_id}"
        )
      end

      decision
    end

    # Pure re-evaluation without recording — used for replay/determinism checks.
    def evaluate(supporter_id:, scope:, at:, as_of_seq: nil)
      projection = build_projection(as_of_seq: as_of_seq)
      Engine.new(projection).evaluate(supporter_id: supporter_id, scope: scope, at: normalize_time(at))
    end

    def build_projection(as_of_seq: nil)
      events = @store.load_events(max_seq: as_of_seq)
      Projection.build(events, as_of_seq: as_of_seq)
    end

    def events(max_seq: nil)
      @store.load_events(max_seq: max_seq)
    end

    def max_seq
      @store.max_seq
    end

    private

    def append(type, payload, event_time, request_id: nil)
      @store.append(type: type, event_time: event_time || Time.now.utc, payload: payload, request_id: request_id)
    end

    # Rebuild the original Decision from a previously recorded DECISION_REQUESTED
    # event, so a replayed decision returns byte-identical anchors and chain.
    def decision_from_event(event)
      p = event.payload
      Engine::Decision.new(
        authorized: p["authorized"],
        reason_code: p["reasonCode"],
        authority_chain: p["authorityChain"],
        supporter_id: p["supporterId"],
        scope: p["scope"],
        event_time: Instant.parse(p["at"]),
        as_of_seq: p["asOfSeq"]
      )
    end

    def require_present!(value, name)
      raise ValidationError, "#{name} is required" if value.nil? || (value.respond_to?(:empty?) && value.empty?)
    end

    def normalize_time(value)
      return nil if value.nil?

      Instant.parse(value).iso8601
    end
  end
end
