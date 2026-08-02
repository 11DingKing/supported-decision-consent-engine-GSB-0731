require_relative "test_helper"

class ReplayAndImmutabilityTest < Minitest::Test
  def test_decision_pins_seen_sequence_and_is_replayable
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A",
                  scopes: ["LEGAL_AID_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z")

    decision = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "A",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )

    assert_equal "AUTHORIZED", decision.reason_code
    assert_equal 1, decision.seen_sequence
    refute_nil decision.decision_id

    recorded = store.find_decision(decision.decision_id)
    assert_equal 1, recorded.payload["seenSequence"]
    assert_equal "AUTHORIZED", recorded.payload["reasonCode"]
    assert_equal ["C1"], recorded.payload["chain"].map { |l| l["id"] }

    verify = store.verify_replay(decision.decision_id)
    assert verify[:reason_code_matches], "reason code must reproduce on replay"
    assert verify[:chain_matches], "chain must reproduce on replay"
    assert_equal decision.seen_sequence, verify[:seen_sequence]
  end

  def test_historical_decision_does_not_change_after_later_revocation
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A",
                  scopes: ["LEGAL_AID_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z")

    historical = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "A",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )
    assert_equal "AUTHORIZED", historical.reason_code
    historical_seq = historical.seen_sequence

    revoke_consent(store, revocation_id: "R1", consent_id: "C1",
                   at: "2026-09-15T10:00:00Z")

    after_revoke = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "A",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-16T00:00:00Z",
      policy: default_policy
    )
    assert_equal "REVOKED", after_revoke.reason_code

    verify = store.verify_replay(historical.decision_id)
    assert verify[:reason_code_matches],
           "historical decision must remain AUTHORIZED on replay despite later revocation"
    assert verify[:chain_matches]
    assert_equal historical_seq, verify[:seen_sequence]
    assert_equal "AUTHORIZED", verify[:recomputed_reason_code]
  end

  def test_replay_across_full_event_prefix_is_deterministic
    store = fresh_store
    seed_authoritative(store)

    decision = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )

    verify = store.verify_replay(decision.decision_id)
    assert verify[:reason_code_matches]
    assert verify[:chain_matches]
    assert_equal ["CONSENT-1", "DELEG-OK"],
                 verify[:recomputed_chain].map { |l| l["id"] }

    3.times do
      again = store.verify_replay(decision.decision_id)
      assert_equal verify[:recomputed_reason_code], again[:recomputed_reason_code]
      assert_equal JSON.generate(verify[:recomputed_chain]),
                   JSON.generate(again[:recomputed_chain])
    end
  end

  def test_events_are_append_only_and_immutable
    store = fresh_store
    e1 = grant_consent(store, consent_id: "C1", supporter: "A",
                       scopes: ["LEGAL_AID_APPLICATION"],
                       from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z")

    assert_equal 1, e1.sequence

    e2 = revoke_consent(store, revocation_id: "R1", consent_id: "C1",
                        at: "2026-09-15T10:00:00Z")
    assert_equal 2, e2.sequence

    reread = store.find_event(1)
    assert_equal e1.event_id, reread.event_id
    assert_equal "ConsentGranted", reread.type
    assert_equal e1.payload["consentId"], reread.payload["consentId"]

    assert_raises do
      store.send(:with_db) do |db|
        db.execute("UPDATE events SET payload = ? WHERE sequence = 1",
                   [JSON.generate({ "tampered" => true })])
      end
    end
  end

  def test_sequence_monotonic_under_repeated_appends
    store = fresh_store
    sequences = 10.times.map do |i|
      e = grant_consent(store, consent_id: "C#{i}", supporter: "A",
                        scopes: ["LEGAL_AID_APPLICATION"],
                        from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z",
                        witness: "W-#{i}")
      e.sequence
    end
    assert_equal sequences, sequences.sort
    assert_equal sequences.uniq, sequences
  end

  def test_decision_records_complete_chain_for_multi_level_delegation
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A",
                  scopes: ["LEGAL_AID_APPLICATION", "HOUSING_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z")
    delegate(store, delegation_id: "D1", source_consent: "C1", from_sup: "A", to_sup: "B",
             scopes: ["LEGAL_AID_APPLICATION"], occurred_at: "2026-08-02T00:00:00Z")
    delegate(store, delegation_id: "D2", source_consent: "C1", from_sup: "B", to_sup: "C",
             scopes: ["LEGAL_AID_APPLICATION"], occurred_at: "2026-08-03T00:00:00Z")

    decision = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "C",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )

    assert_equal "AUTHORIZED", decision.reason_code
    chain_ids = decision.chain.map(&:id)
    assert_equal ["C1", "D1", "D2"], chain_ids

    decision.chain.each do |link|
      assert link.scopes.include?("LEGAL_AID_APPLICATION")
    end

    verify = store.verify_replay(decision.decision_id)
    assert verify[:chain_matches]
  end
end
