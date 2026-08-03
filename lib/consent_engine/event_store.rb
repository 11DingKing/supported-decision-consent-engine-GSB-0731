# frozen_string_literal: true

require_relative "reason_codes"
require_relative "event"
require_relative "authorization_decision"
require_relative "authorizer"

module ConsentEngine
  # In-memory, append-only event store. The HTTP/persistence layers can wrap
  # this. All authorization logic runs over events returned by #events.
  class EventStore
    class DuplicateEventId < StandardError; end
    class EventFromPast < StandardError; end

    attr_reader :clock

    def initialize
      @events = []
      @mutex  = Mutex.new
      @clock  = -> { Time.now.utc }
    end

    # Inject a clock (useful for deterministic tests).
    def clock=(callable)
      @clock = callable
    end

    # Append a new event. Returns the newly-created Event with seq assigned.
    #
    # Options:
    #   event_id:, type:, payload:, effective_at:
    #
    # +effective_at+ defaults to the observed time. Out-of-order business times
    # are allowed (a revocation may have an effective_at in the past relative
    # to other events), but we NEVER allow a new event to be inserted behind
    # the current high seq — history is immutable.
    def append(event_id:, type:, payload:, effective_at: nil)
      observed = @clock.call
      effective = effective_at ? coerce_time(effective_at) : observed

      @mutex.synchronize do
        if @events.any? { |e| e.event_id == event_id }
          raise DuplicateEventId, "event_id=#{event_id} already exists"
        end
        seq = (@events.map(&:seq).max || 0) + 1
        ev = Event.new(
          seq: seq,
          event_id: event_id,
          type: type,
          observed_at: observed,
          effective_at: effective,
          payload: deep_freeze(payload)
        )
        @events << ev
        ev
      end
    end

    # Snapshot for a decision: all events with seq <= seen_seq.
    # If seen_seq is nil, use the current high-water mark.
    def snapshot(seen_seq: nil)
      @mutex.synchronize do
        max = seen_seq || (@events.map(&:seq).max || 0)
        @events.select { |e| e.seq <= max }.sort_by(&:seq).map(&:dup)
      end
    end

    def high_seq
      @mutex.synchronize { @events.map(&:seq).max || 0 }
    end

    def all
      @mutex.synchronize { @events.dup }
    end

    def find_event(event_id)
      @mutex.synchronize { @events.find { |e| e.event_id == event_id } }
    end

    def reset!
      @mutex.synchronize { @events.clear }
    end

    private

    def coerce_time(t)
      return t if t.is_a?(Time)
      Time.iso8601(t.to_s)
    end

    def deep_freeze(obj)
      case obj
      when Hash
        obj.each { |k, v| deep_freeze(k); deep_freeze(v) }
        obj.freeze
      when Array
        obj.each { |v| deep_freeze(v) }
        obj.freeze
      else
        obj.freeze unless obj.is_a?(Numeric) || obj.is_a?(TrueClass) || obj.is_a?(FalseClass)
      end
      obj
    end
  end
end
