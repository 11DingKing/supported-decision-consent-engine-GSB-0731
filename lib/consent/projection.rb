# frozen_string_literal: true

require_relative "instant"

module Consent
  # Immutable value records folded out of the event log. They carry the raw
  # temporal metadata (windows, revocation instants) but make NO authority
  # judgement themselves — the engine applies as-of-time semantics. This keeps
  # "what was recorded" (projection) separate from "what it authorizes now"
  # (engine), which is what lets a replay at a fixed (time, seq) reproduce the
  # same answer regardless of later events.

  Person = Struct.new(:id, keyword_init: true)
  Supporter = Struct.new(:id, keyword_init: true)
  ScopeDef = Struct.new(:name, keyword_init: true)

  Consent_ = Struct.new(
    :id, :supporter_id, :scopes, :from, :to, :witness_id,
    :revoked_at, :granted_seq,
    keyword_init: true
  )

  Delegation = Struct.new(
    :id, :source_consent_id, :from_supporter_id, :to_supporter_id,
    :scopes, :from, :to, :revoked_at, :created_seq,
    keyword_init: true
  )

  Emergency = Struct.new(
    :id, :supporter_id, :scope, :invoked_at, :max_minutes,
    :reviewed_at, :created_seq,
    keyword_init: true
  )

  EmergencyPolicy = Struct.new(
    :allowed_scope, :max_minutes, :requires_review_event,
    keyword_init: true
  )

  # Projection is a pure fold. Given an ordered event list and an audit
  # ceiling, it reconstructs the world exactly as it had been recorded up to
  # that seq. Events with seq > as_of_seq are invisible: this is the guard
  # that stops a concurrently-appended fact from altering a past decision.
  class Projection
    attr_reader :persons, :supporters, :scopes, :consents, :delegations,
                :emergencies, :emergency_policy, :as_of_seq

    def self.build(events, as_of_seq: nil)
      new(events, as_of_seq: as_of_seq)
    end

    def initialize(events, as_of_seq: nil)
      @persons = {}
      @supporters = {}
      @scopes = {}
      @consents = {}
      @delegations = {}
      @emergencies = {}
      @emergency_policy = nil
      @as_of_seq = as_of_seq

      visible = events.select { |e| as_of_seq.nil? || e.seq <= as_of_seq }
      # Fold strictly in audit order; recorded facts are applied by seq.
      visible.sort_by(&:seq).each { |e| apply(e) }
    end

    def supporter?(id)
      @supporters.key?(id)
    end

    def scope?(name)
      @scopes.key?(name)
    end

    private

    def apply(event)
      case event.type
      when "PERSON_REGISTERED"
        id = event.payload["personId"]
        @persons[id] = Person.new(id: id)
      when "SUPPORTER_ADDED"
        id = event.payload["supporterId"]
        @supporters[id] = Supporter.new(id: id)
      when "SCOPE_DEFINED"
        name = event.payload["scope"]
        @scopes[name] = ScopeDef.new(name: name)
      when "CONSENT_GRANTED"
        p = event.payload
        @consents[p["id"]] = Consent_.new(
          id: p["id"],
          supporter_id: p["supporterId"],
          scopes: Array(p["scopes"]).uniq,
          from: Instant.parse(p["from"]),
          to: Instant.parse(p["to"]),
          witness_id: p["witnessId"],
          revoked_at: nil,
          granted_seq: event.seq
        )
      when "CONSENT_REVOKED"
        c = @consents[event.payload["consentId"]]
        if c
          at = Instant.parse(event.payload["at"] || event.event_time&.iso8601)
          # First revocation wins; revocation is monotonic and cannot be
          # loosened by a later event.
          c.revoked_at = at if c.revoked_at.nil? || at < c.revoked_at
        end
      when "DELEGATION_CREATED"
        p = event.payload
        @delegations[p["id"]] = Delegation.new(
          id: p["id"],
          source_consent_id: p["sourceConsentId"],
          from_supporter_id: p["fromSupporterId"],
          to_supporter_id: p["toSupporterId"],
          scopes: Array(p["scopes"]).uniq,
          from: Instant.parse(p["from"]),
          to: Instant.parse(p["to"]),
          revoked_at: nil,
          created_seq: event.seq
        )
      when "DELEGATION_REVOKED"
        d = @delegations[event.payload["delegationId"]]
        if d
          at = Instant.parse(event.payload["at"] || event.event_time&.iso8601)
          d.revoked_at = at if d.revoked_at.nil? || at < d.revoked_at
        end
      when "EMERGENCY_INVOKED"
        p = event.payload
        @emergencies[p["id"]] = Emergency.new(
          id: p["id"],
          supporter_id: p["supporterId"],
          scope: p["scope"],
          invoked_at: Instant.parse(p["at"] || event.event_time&.iso8601),
          max_minutes: p["maxMinutes"],
          reviewed_at: nil,
          created_seq: event.seq
        )
      when "EMERGENCY_REVIEWED"
        e = @emergencies[event.payload["emergencyId"]]
        if e
          at = Instant.parse(event.payload["at"] || event.event_time&.iso8601)
          e.reviewed_at = at if e.reviewed_at.nil? || at < e.reviewed_at
        end
      when "EMERGENCY_POLICY_SET"
        p = event.payload
        @emergency_policy = EmergencyPolicy.new(
          allowed_scope: p["allowedScope"],
          max_minutes: p["maxMinutes"],
          requires_review_event: p["requiresReviewEvent"]
        )
      when "DECISION_REQUESTED"
        # Decisions are recorded for audit but do not change state.
        nil
      end
    end
  end
end
