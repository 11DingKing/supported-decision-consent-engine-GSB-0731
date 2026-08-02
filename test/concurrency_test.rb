require_relative "test_helper"

class ConcurrencyTest < Minitest::Test
  def test_concurrent_grant_and_revocation_never_expands_scope
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A",
                  scopes: ["LEGAL_AID_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z")

    decision_time = "2026-09-15T10:00:00Z"

    threads = 20.times.map do |i|
      Thread.new do
        if i.even?
          revoke_consent(store, revocation_id: "R-#{i}", consent_id: "C1",
                         at: decision_time)
        end
        store.evaluate_decision(
          person_id: "PERSON-01", supporter_id: "A",
          scope: "LEGAL_AID_APPLICATION", at: decision_time,
          policy: default_policy
        )
      end
    end

    results = threads.map(&:value)

    assert(results.all? { |r| r.is_a?(ConsentEngine::Domain::DecisionResult) })

    authorized = results.select(&:authorized?)
    denied = results.reject(&:authorized?)

    denied.each do |r|
      assert_equal "REVOKED", r.reason_code,
                   "denied decisions must be REVOKED, got #{r.reason_code}"
    end

    authorized.each do |r|
      assert_equal "AUTHORIZED", r.reason_code
      assert_equal ["C1"], r.chain.map(&:id)
    end

    sequences = results.map(&:seen_sequence)
    assert sequences.all? { |s| s.is_a?(Integer) && s >= 1 }

    assert (authorized.length + denied.length) == 20
  end

  def test_concurrent_appends_preserve_monotonic_sequences
    store = fresh_store

    threads = 10.times.map do |i|
      Thread.new do
        5.times.map do |j|
          e = store.append(
            event_type: "ConsentGranted",
            event_id: "CC-#{i}-#{j}",
            person_id: "PERSON-01",
            occurred_at: "2026-08-01T00:00:00Z",
            payload: {
              "consentId" => "CC-#{i}-#{j}",
              "supporterId" => "A",
              "scopes" => ["LEGAL_AID_APPLICATION"],
              "validFrom" => "2026-08-01T00:00:00Z",
              "validTo" => "2026-12-01T00:00:00Z",
              "witnessId" => "W"
            }
          )
          e.sequence
        end
      end
    end

    all_sequences = threads.flat_map(&:value)
    assert_equal 50, all_sequences.length
    assert_equal 50, all_sequences.uniq.length
    assert_equal (1..50).to_a, all_sequences.sort
  end

  def test_inflight_decision_at_exact_revocation_instant_is_deterministic
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A",
                  scopes: ["LEGAL_AID_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z")

    revocation_time = "2026-09-15T10:00:00Z"

    pre_existing = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "A",
      scope: "LEGAL_AID_APPLICATION", at: revocation_time,
      policy: default_policy
    )
    assert_equal "AUTHORIZED", pre_existing.reason_code
    pre_seq = pre_existing.seen_sequence

    revoke_consent(store, revocation_id: "R1", consent_id: "C1",
                   at: revocation_time)

    at_exact = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "A",
      scope: "LEGAL_AID_APPLICATION", at: revocation_time,
      policy: default_policy
    )
    assert_equal "REVOKED", at_exact.reason_code,
                 "at the exact revocation instant consent must be treated as revoked"
    assert at_exact.seen_sequence > pre_seq

    pre_verify = store.verify_replay(pre_existing.decision_id)
    assert pre_verify[:reason_code_matches],
           "the in-flight decision pinned before revocation must remain AUTHORIZED on replay"
    assert_equal "AUTHORIZED", pre_verify[:recomputed_reason_code]
  end

  def test_race_cannot_expand_scope_via_delegation
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A",
                  scopes: ["LEGAL_AID_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z")

    threads = 10.times.map do |i|
      Thread.new do
        begin
          store.append(
            event_type: "DelegationGranted",
            event_id: "D-BROAD-#{i}",
            person_id: "PERSON-01",
            occurred_at: "2026-08-02T00:00:00Z",
            payload: {
              "delegationId" => "D-BROAD-#{i}",
              "sourceConsentId" => "C1",
              "fromSupporterId" => "A",
              "toSupporterId" => "B",
              "scopes" => ["MEDICAL_INFORMATION_VIEW"],
              "validTo" => nil
            }
          )
        rescue
        end
        store.evaluate_decision(
          person_id: "PERSON-01", supporter_id: "B",
          scope: "MEDICAL_INFORMATION_VIEW", at: "2026-09-01T00:00:00Z",
          policy: default_policy
        )
      end
    end

    results = threads.map(&:value)
    results.each do |r|
      refute r.authorized?, "broad delegation must never authorize MEDICAL scope"
      assert_equal "DELEGATION_BROADER_THAN_SOURCE", r.reason_code
    end
  end

  def test_emergency_timeout_is_race_safe
    store = fresh_store
    start_emergency(store, emergency_id: "E1", scope: "LEGAL_AID_APPLICATION",
                    started_at: "2026-09-01T10:00:00Z")

    times = [
      "2026-09-01T10:29:59Z",
      "2026-09-01T10:30:00Z",
      "2026-09-01T10:30:01Z"
    ]

    results = times.map do |time|
      store.evaluate_decision(
        person_id: "PERSON-01", supporter_id: "ANY",
        scope: "LEGAL_AID_APPLICATION", at: time,
        policy: default_policy
      )
    end

    assert results[0].authorized?
    assert_equal "EMERGENCY_AUTHORIZED", results[0].reason_code
    refute results[1].authorized?
    assert_equal "EMERGENCY_TIMEOUT", results[1].reason_code
    refute results[2].authorized?
    assert_equal "EMERGENCY_TIMEOUT", results[2].reason_code
  end
end
