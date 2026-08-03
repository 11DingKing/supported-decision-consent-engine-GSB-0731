# frozen_string_literal: true

require_relative "test_helper"
require_relative "../lib/consent_engine/sqlite_event_store"

# Determinism / concurrency / persistence tests.
#
# Threat model: any race between a grant and a revoke, or between decisions
# and later writes, must not expand scope or rewrite history.
class DeterminismTest < Minitest::Test
  include TestHelpers

  def test_same_events_same_result_independent_of_wall_clock
    service = build_service
    seed_person_and_supporter(service, "P1", %w[S1])
    service.grant_consent(
      consent_id: "C1", person_id: "P1", supporter_id: "S1",
      scopes: %w[HOUSING], from: "2026-08-01T00:00:00Z",
      to: "2026-12-01T00:00:00Z", witness_id: "W1",
      effective_at: "2026-08-01T00:00:00Z"
    )
    service.revoke_consent(
      revocation_id: "R1", consent_id: "C1",
      at: "2026-09-15T10:00:00Z", effective_at: "2026-09-15T10:00:00Z"
    )

    # Two calls at the same business time, even with different wall clocks,
    # must agree on reason code and chain.
    service.store.clock = fixed_clock("2030-01-01T00:00:00Z")
    d1 = service.decide(person_id: "P1", supporter_id: "S1", scope: "HOUSING", as_of: "2026-09-20T00:00:00Z")

    service.store.clock = fixed_clock("2010-01-01T00:00:00Z")
    d2 = service.decide(person_id: "P1", supporter_id: "S1", scope: "HOUSING", as_of: "2026-09-20T00:00:00Z")

    assert_equal d1.reason_code, d2.reason_code
    assert_equal d1.granted?, d2.granted?
    assert_equal d1.chain.map(&:event_id), d2.chain.map(&:event_id)
  end

  def test_seen_seq_pins_snapshot
    service = build_service
    seed_person_and_supporter(service, "P1", %w[S1])
    service.grant_consent(
      consent_id: "C1", person_id: "P1", supporter_id: "S1",
      scopes: %w[HOUSING], from: "2026-08-01T00:00:00Z",
      to: "2026-12-01T00:00:00Z", witness_id: "W1",
      effective_at: "2026-08-01T00:00:00Z"
    )
    d1 = service.decide(person_id: "P1", supporter_id: "S1", scope: "HOUSING", as_of: "2026-09-01T00:00:00Z")
    pinned = d1.seen_seq

    # Later revoke — but replay at pinned seq is still granted.
    service.revoke_consent(
      revocation_id: "R1", consent_id: "C1",
      at: "2026-09-15T10:00:00Z", effective_at: "2026-09-15T10:00:00Z"
    )
    d2 = service.decide(person_id: "P1", supporter_id: "S1", scope: "HOUSING", as_of: "2026-09-01T00:00:00Z", seen_seq: pinned)
    assert d2.granted?
    assert_equal ConsentEngine::ReasonCodes::GRANTED, d2.reason_code
    assert_equal pinned, d2.seen_seq
  end

  def test_concurrent_writers_preserve_sequential_integrity
    store = ConsentEngine::EventStore.new
    store.clock = fixed_clock("2026-08-01T00:00:00Z")
    service = ConsentEngine::Service.new(store: store)
    service.register_person("P1")
    20.times { |i| service.register_supporter("S#{i}") }

    errors = []
    threads = 20.times.map do |i|
      Thread.new do
        begin
          service.grant_consent(
            consent_id: "CC-#{i}", person_id: "P1", supporter_id: "S#{i}",
            scopes: %w[HOUSING], from: "2026-08-01T00:00:00Z",
            to: "2026-12-01T00:00:00Z", witness_id: "W1",
            effective_at: "2026-08-01T00:00:00Z"
          )
        rescue => e
          errors << e
        end
      end
    end
    threads.each(&:join)
    assert_empty errors

    seqs = store.all.map(&:seq)
    assert_equal seqs.sort, seqs
    assert_equal seqs.uniq.size, seqs.size
  end

  def test_sqlite_persistence_roundtrip
    Dir.mktmpdir do |dir|
      path = File.join(dir, "audit.db")
      store1 = ConsentEngine::SQLiteEventStore.new(path)
      store1.clock = fixed_clock("2026-08-01T00:00:00Z")
      svc1 = ConsentEngine::Service.new(store: store1)
      svc1.register_person("P1")
      svc1.register_supporter("S1")
      svc1.grant_consent(
        consent_id: "C1", person_id: "P1", supporter_id: "S1",
        scopes: %w[HOUSING], from: "2026-08-01T00:00:00Z",
        to: "2026-12-01T00:00:00Z", witness_id: "W1",
        effective_at: "2026-08-01T00:00:00Z"
      )
      d1 = svc1.decide(person_id: "P1", supporter_id: "S1", scope: "HOUSING", as_of: "2026-09-01T00:00:00Z")
      store1.close

      store2 = ConsentEngine::SQLiteEventStore.new(path)
      svc2 = ConsentEngine::Service.new(store: store2)
      d2 = svc2.decide(person_id: "P1", supporter_id: "S1", scope: "HOUSING", as_of: "2026-09-01T00:00:00Z")
      assert_equal d1.reason_code, d2.reason_code
      assert_equal d1.granted?, d2.granted?
      assert_equal d1.chain.map(&:event_id), d2.chain.map(&:event_id)
      store2.close
    end
  end

  def test_sqlite_duplicate_event_id_rejected
    Dir.mktmpdir do |dir|
      store = ConsentEngine::SQLiteEventStore.new(File.join(dir, "a.db"))
      store.append(event_id: "E1", type: "PERSON_REGISTERED", payload: { "personId" => "P1" })
      assert_raises(ConsentEngine::SQLiteEventStore::DuplicateEventId) do
        store.append(event_id: "E1", type: "PERSON_REGISTERED", payload: { "personId" => "P1" })
      end
      store.close
    end
  end

  def test_authoritative_cases_file_loads_and_decides
    svc = ConsentEngine.build_from_cases(File.expand_path("../materials/consent-cases.json", __dir__))
    # Before revocation: SUPPORTER-A has LEGAL_AID_APPLICATION directly.
    d = svc.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z"
    )
    assert d.granted?
    assert_equal ConsentEngine::ReasonCodes::GRANTED, d.reason_code

    # After revocation: denied.
    d2 = svc.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-20T00:00:00Z"
    )
    refute d2.granted?
    assert_equal ConsentEngine::ReasonCodes::REVOKED, d2.reason_code

    # SUPPORTER-B via DELEG-OK: the chain itself is valid, but a sibling
    # DELEG-BROAD carries MEDICAL_INFORMATION_VIEW which is outside the
    # source consent's scope set. The cumulative scope-union budget is
    # exceeded (Round 2), so B is denied with a stable non-scope-leaking code.
    d3 = svc.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z"
    )
    refute d3.granted?
    assert_equal ConsentEngine::ReasonCodes::DELEGATION_BUDGET_EXCEEDED, d3.reason_code
    assert_equal %w[CONSENT-1 DELEG-OK], d3.chain.map(&:event_id)

    # DELEG-BROAD attempts MEDICAL_INFORMATION_VIEW but source lacks it.
    # The hop itself is broad, so the more specific DELEGATION_BROAD is
    # returned (rather than the cumulative budget code).
    d4 = svc.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "MEDICAL_INFORMATION_VIEW", as_of: "2026-09-01T00:00:00Z"
    )
    refute d4.granted?
    assert_equal ConsentEngine::ReasonCodes::DELEGATION_BROAD, d4.reason_code

    # Exact revocation instant: denied.
    d5 = svc.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-15T10:00:00Z"
    )
    refute d5.granted?
    assert_equal ConsentEngine::ReasonCodes::REVOKED, d5.reason_code
  end
end
