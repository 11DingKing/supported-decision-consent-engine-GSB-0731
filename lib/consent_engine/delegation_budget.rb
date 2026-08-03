# frozen_string_literal: true

require "time"

module ConsentEngine
  # Pure-domain budget checker for sub-delegations under a single source
  # consent. Given:
  #   * the source consent event (scope set, validity window, emergency budget)
  #   * all sibling DELEGATION_GRANTED events that cite this source
  #   * the decision time and seq high-water mark
  # it answers: does the aggregate of all those siblings stay within the
  # source's delegated authority?
  #
  # Three dimensions are checked:
  #   1. Scope count / union — the union of delegated scopes across siblings
  #      must be a subset of the source scopes.
  #   2. Time window — every delegation's +to+ must be <= source +to+. The
  #      longest delegated window cannot exceed the source's own validity.
  #   3. Emergency minutes — when a source consent carries an
  #      +emergencyMinutes+ budget, the sum of +emergencyMinutes+ across all
  #      siblings must not exceed it.
  #
  # This class performs NO I/O and is deterministic given its inputs.
  class DelegationBudget
    class Exceeded < StandardError
      attr_reader :dimension, :detail
      def initialize(dimension, detail)
        @dimension = dimension
        @detail    = detail
        super("delegation budget exceeded: #{dimension} (#{detail})")
      end
    end

    attr_reader :source_event, :siblings, :decision_at, :seen_seq

    # @param source_event  Event  the CONSENT_GRANTED event that is the root
    # @param siblings      Array[Event] DELEGATION_GRANTED events whose
    #                      sourceConsentId == source_event.event_id
    # @param decision_at   Time
    # @param seen_seq      Integer
    # @param emergency_activations Array[Event] EMERGENCY_ACTIVATED events
    #                      that have consumed some of the source's emergency
    #                      budget. Each activation is counted as
    #                      +emergencyMinutes+ (defaulting to the system
    #                      max_minutes). This consumed budget survives
    #                      revocation — it cannot be reset by revoking and
    #                      re-granting.
    def initialize(source_event, siblings, decision_at, seen_seq, emergency_activations: [])
      @source_event         = source_event
      @siblings             = siblings
      @decision_at          = decision_at
      @seen_seq             = seen_seq
      @emergency_activations = emergency_activations
    end

    # Raises Exceeded if the aggregate budget is violated; returns true
    # otherwise. A result object is also returned describing the tallied
    # totals, which can be attached to the audit chain.
    def verify!
      verify_scope_union!
      verify_time_window!
      verify_emergency_minutes!
      true
    end

    # Numeric / structural totals without raising.
    def totals
      {
        delegated_scope_count:  delegated_scope_union.size,
        source_scope_count:     source_scopes.size,
        longest_delegation_end: longest_delegation_end&.utc&.iso8601,
        source_end:             source_end_time&.utc&.iso8601,
        total_emergency_minutes: total_emergency_minutes,
        source_emergency_minutes: source_emergency_minutes,
        sibling_count:          @siblings.size
      }
    end

    private

    def source_scopes
      Array(@source_event.payload["scopes"])
    end

    def source_end_time
      @source_event.payload["to"] ? Time.iso8601(@source_event.payload["to"]) : nil
    end

    def source_emergency_minutes
      @source_event.payload["emergencyMinutes"]
    end

    def delegated_scope_union
      @siblings.flat_map { |d| Array(d.payload["scopes"]) }.uniq
    end

    def longest_delegation_end
      @siblings
        .map    { |d| d.payload["to"] ? Time.iso8601(d.payload["to"]) : nil }
        .compact
        .max
    end

    def total_emergency_minutes
      delegated = @siblings.sum { |d| (d.payload["emergencyMinutes"] || 0).to_i }
      activated = @emergency_activations.sum do |a|
        (a.payload["emergencyMinutes"] || 0).to_i
      end
      delegated + activated
    end

    # --- checks ---

    def verify_scope_union!
      union = delegated_scope_union
      excess = union - source_scopes
      return if excess.empty?
      raise Exceeded.new(:scope, "union contains scopes not in source: count=#{excess.size}")
    end

    def verify_time_window!
      src_end = source_end_time
      return unless src_end
      long_end = longest_delegation_end
      return unless long_end
      if long_end > src_end
        raise Exceeded.new(:time, "delegation ends at #{long_end.iso8601} after source #{src_end.iso8601}")
      end
    end

    def verify_emergency_minutes!
      budget = source_emergency_minutes
      return if budget.nil?
      used = total_emergency_minutes
      if used > budget.to_i
        raise Exceeded.new(:emergency_minutes, "used=#{used} budget=#{budget}")
      end
    end
  end
end
