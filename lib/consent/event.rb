# frozen_string_literal: true

require "digest"
require_relative "canonical_json"
require_relative "instant"

module Consent
  # An Event is an immutable, recorded fact. The authorization engine never
  # mutates events; it only folds them into a projection. Two coordinates
  # anchor every fact:
  #
  #   * seq         - monotonic audit sequence, assigned at append time by the
  #                   store. Establishes "what had been recorded" ordering.
  #   * event_time  - the domain instant at which the fact takes effect. May
  #                   differ from wall-clock append order (back- or post-dated).
  #
  # A decision fixes BOTH an as-of event_time and the max audit seq visible at
  # that moment. Replaying with the same pair reconstructs the identical fact
  # set, which is what makes reason codes and authority chains reproducible and
  # prevents a later-appended (higher-seq) fact from rewriting a past decision.
  class Event
    TYPES = %w[
      PERSON_REGISTERED
      SUPPORTER_ADDED
      SCOPE_DEFINED
      EMERGENCY_POLICY_SET
      CONSENT_GRANTED
      CONSENT_REVOKED
      DELEGATION_CREATED
      DELEGATION_REVOKED
      EMERGENCY_INVOKED
      EMERGENCY_REVIEWED
      EMERGENCY_CONSUMED
      EMERGENCY_REVOKED
      DECISION_REQUESTED
    ].freeze

    attr_reader :seq, :type, :event_time, :payload, :recorded_at, :prev_hash, :hash_value

    def initialize(seq:, type:, event_time:, payload:, recorded_at:, prev_hash:, hash_value: nil)
      raise ArgumentError, "unknown event type: #{type}" unless TYPES.include?(type)

      @seq = seq
      @type = type
      @event_time = Instant.parse(event_time)
      @payload = payload || {}
      @recorded_at = Instant.parse(recorded_at)
      @prev_hash = prev_hash
      @hash_value = hash_value || compute_hash
    end

    # Deterministic content hash chaining this event to its predecessor. Any
    # tampering with a stored field (or reordering) breaks the chain and is
    # detectable by re-deriving hashes during load.
    def compute_hash
      material = CanonicalJSON.dump(
        "seq" => seq,
        "type" => type,
        "event_time" => event_time&.iso8601,
        "payload" => payload,
        "recorded_at" => recorded_at&.iso8601,
        "prev_hash" => prev_hash
      )
      Digest::SHA256.hexdigest(material)
    end

    def valid_hash?
      hash_value == compute_hash
    end

    def to_h
      {
        "seq" => seq,
        "type" => type,
        "event_time" => event_time&.iso8601,
        "payload" => payload,
        "recorded_at" => recorded_at&.iso8601,
        "prev_hash" => prev_hash,
        "hash" => hash_value
      }
    end
  end
end
