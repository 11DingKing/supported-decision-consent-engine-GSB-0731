# frozen_string_literal: true

require "minitest/autorun"
require_relative "../lib/consent_engine"

# Shared helper for building a fresh in-memory service.
module TestHelpers
  def build_service(emergency: nil)
    store = ConsentEngine::EventStore.new
    ConsentEngine::Service.new(store: store, emergency_config: emergency)
  end

  def seed_person_and_supporter(service, person_id = "P1", supporters = %w[S1 S2])
    service.register_person(person_id)
    supporters.each { |s| service.register_supporter(s) }
  end

  # Fixed clock so tests are deterministic regardless of wall clock.
  def fixed_clock(t)
    -> { Time.iso8601(t) }
  end
end
