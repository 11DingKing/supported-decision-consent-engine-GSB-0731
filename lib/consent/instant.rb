# frozen_string_literal: true

require "time"

module Consent
  # Instant wraps a UTC point in time and gives the domain a single, explicit
  # comparison semantics. Every authorization decision is anchored to an
  # "as-of" Instant so evaluations are pure functions of recorded facts.
  #
  # Boundary rule (documented once, applied everywhere):
  #   * A validity window is [from, to): effective when from <= t < to.
  #   * A revocation takes effect at its instant: a decision AT the exact
  #     revocation instant is treated as revoked (t >= revoked_at => revoked).
  # These closed/open choices make "the decision at the exact revocation
  # instant" deterministic rather than a coin flip.
  class Instant
    include Comparable

    attr_reader :time

    def self.parse(value)
      return value if value.is_a?(Instant)
      return nil if value.nil?

      t =
        case value
        when Time    then value
        when Integer then Time.at(value)
        when String  then Time.iso8601(value)
        else raise ArgumentError, "unsupported time value: #{value.inspect}"
        end
      new(t.utc)
    end

    def initialize(time)
      @time = time.utc
    end

    def <=>(other)
      return nil unless other.is_a?(Instant)

      time <=> other.time
    end

    # Effective within [from, to). Nil bounds mean unbounded on that side.
    def within?(from, to)
      return false if from && self < from
      return false if to && self >= to

      true
    end

    # A revocation/expiry at `at` is in force once self reaches it.
    def at_or_after?(at)
      return false if at.nil?

      self >= at
    end

    def iso8601
      time.iso8601
    end

    def to_s
      iso8601
    end

    def hash
      time.to_r.hash
    end

    def eql?(other)
      other.is_a?(Instant) && (self <=> other).zero?
    end
  end
end
