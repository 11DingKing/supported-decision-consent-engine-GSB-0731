# frozen_string_literal: true

require "time"
require "json"

module ConsentEngine
  # Immutable audit event. Events are append-only and never mutated.
  # +seq+ is the monotonic SQLite insertion sequence; +observed_at+ is the
  # server receive time (used to answer "what events existed as of T").
  # +effective_at+ is the business time supplied by the caller (the moment
  # at which a grant / revoke / delegation takes legal effect).
  class Event
    TYPES = %w[
      PERSON_REGISTERED
      SUPPORTER_REGISTERED
      CONSENT_GRANTED
      CONSENT_REVOKED
      DELEGATION_GRANTED
      EMERGENCY_ACTIVATED
      EMERGENCY_REVIEWED
      DECISION_RECORDED
    ].freeze

    attr_reader :seq, :event_id, :type, :observed_at, :effective_at, :payload

    def initialize(seq:, event_id:, type:, observed_at:, effective_at:, payload:)
      raise ArgumentError, "unknown type #{type}" unless TYPES.include?(type)

      @seq          = seq
      @event_id     = event_id
      @type         = type
      @observed_at  = _parse(observed_at)
      @effective_at = _parse(effective_at)
      @payload      = payload.dup.freeze
      freeze
    end

    def to_h
      {
        seq: seq,
        event_id: event_id,
        type: type,
        observed_at: observed_at.utc.iso8601,
        effective_at: effective_at.utc.iso8601,
        payload: payload
      }
    end

    private

    def _parse(t)
      t.is_a?(Time) ? t : Time.iso8601(t.to_s)
    end
  end
end
