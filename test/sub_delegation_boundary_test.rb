require_relative "test_helper"

class SubDelegationBoundaryTest < Minitest::Test
  def setup
    super
    @store = fresh_store
    grant_consent(@store, consent_id: "CONSENT-1", supporter: "SUPPORTER-A",
                  scopes: ["LEGAL_AID_APPLICATION", "HOUSING_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z",
                  witness: "W-1", occurred_at: "2026-08-01T00:00:00Z")
  end

  def test_deleg_ok_authorizes_within_source
    delegate(@store, delegation_id: "DELEG-OK", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-B",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-02T00:00:00Z",
             valid_to: "2026-10-01T00:00:00Z")

    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )

    assert result.authorized?
    assert_equal "AUTHORIZED", result.reason_code
    assert_equal ["CONSENT-1", "DELEG-OK"], result.chain.map(&:id)
    refute result.chain.any?(&:redacted)
  end

  def test_deleg_broad_is_rejected_with_redacted_evidence
    delegate(@store, delegation_id: "DELEG-BROAD", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-B",
             scopes: ["MEDICAL_INFORMATION_VIEW"],
             occurred_at: "2026-08-02T00:00:00Z")

    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "MEDICAL_INFORMATION_VIEW", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )

    refute result.authorized?
    assert_equal "DELEGATION_BROADER_THAN_SOURCE", result.reason_code
    assert_equal ["CONSENT-1", "DELEG-BROAD"], result.chain.map(&:id)
    assert result.chain.all?(&:redacted)
    assert result.chain.all? { |l| l.scopes.to_a.empty? }
    assert result.chain.all? { |l| l.witness_id.nil? }
  end

  def test_concurrent_deleg_ok_and_deleg_broad_both_evaluated_independently
    delegate(@store, delegation_id: "DELEG-OK", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-B",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-02T00:00:00Z",
             valid_to: "2026-10-01T00:00:00Z")
    delegate(@store, delegation_id: "DELEG-BROAD", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-B",
             scopes: ["MEDICAL_INFORMATION_VIEW"],
             occurred_at: "2026-08-02T00:01:00Z")

    legal = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )
    medical = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "MEDICAL_INFORMATION_VIEW", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )

    assert legal.authorized?
    assert_equal ["CONSENT-1", "DELEG-OK"], legal.chain.map(&:id)

    refute medical.authorized?
    assert_equal "DELEGATION_BROADER_THAN_SOURCE", medical.reason_code
    assert medical.chain.all?(&:redacted)
  end

  def test_delegation_duration_exceeding_source_is_rejected
    delegate(@store, delegation_id: "LONG-DELEG", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-B",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-02T00:00:00Z",
             valid_to: "2027-06-01T00:00:00Z")

    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )

    refute result.authorized?
    assert_equal "DELEGATION_DURATION_EXCEEDS_SOURCE", result.reason_code
    assert_equal ["CONSENT-1", "LONG-DELEG"], result.chain.map(&:id)
    assert result.chain.all?(&:redacted)
  end

  def test_individual_emergency_budget_exceeding_source_is_rejected
    delegate(@store, delegation_id: "BUDGET-BIG", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-B",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-02T00:00:00Z",
             valid_to: "2026-10-01T00:00:00Z",
             emergency_budget_minutes: 60)

    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )

    refute result.authorized?
    assert_equal "DELEGATION_BUDGET_EXCEEDED", result.reason_code
    assert result.chain.all?(&:redacted)
  end

  def test_two_sub_chains_cumulative_emergency_budget_exceeded
    delegate(@store, delegation_id: "D1", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-B",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-02T00:00:00Z",
             valid_to: "2026-10-01T00:00:00Z",
             emergency_budget_minutes: 20)
    delegate(@store, delegation_id: "D2", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-C",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-03T00:00:00Z",
             valid_to: "2026-10-01T00:00:00Z",
             emergency_budget_minutes: 20)

    r1 = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )
    r2 = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-C",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )

    refute r1.authorized?, "20+20=40 exceeds source budget of 30"
    assert_equal "DELEGATION_CUMULATIVE_BUDGET_EXCEEDED", r1.reason_code
    refute r2.authorized?
    assert_equal "DELEGATION_CUMULATIVE_BUDGET_EXCEEDED", r2.reason_code
  end

  def test_cumulative_budget_within_limit_authorizes
    delegate(@store, delegation_id: "D1", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-B",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-02T00:00:00Z",
             valid_to: "2026-10-01T00:00:00Z",
             emergency_budget_minutes: 15)
    delegate(@store, delegation_id: "D2", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-C",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-03T00:00:00Z",
             valid_to: "2026-10-01T00:00:00Z",
             emergency_budget_minutes: 15)

    r1 = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )
    r2 = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-C",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )

    assert r1.authorized?
    assert r2.authorized?
  end

  def test_revoked_sub_chain_does_not_count_toward_cumulative_budget
    delegate(@store, delegation_id: "D1", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-B",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-02T00:00:00Z",
             valid_to: "2026-10-01T00:00:00Z",
             emergency_budget_minutes: 20)
    delegate(@store, delegation_id: "D2", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-C",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-03T00:00:00Z",
             valid_to: "2026-10-01T00:00:00Z",
             emergency_budget_minutes: 20)
    revoke_delegation(@store, revocation_id: "DR1", delegation_id: "D1",
                      at: "2026-08-15T00:00:00Z")

    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-C",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )

    assert result.authorized?,
           "revoked D1 should not count; only D2's 20 <= 30"
  end

  def test_source_revoked_before_sub_chain_saved_is_late_arrival
    delegate(@store, delegation_id: "D1", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-B",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-02T00:00:00Z",
             valid_to: "2026-10-01T00:00:00Z")
    revoke_consent(@store, revocation_id: "REV-1", consent_id: "CONSENT-1",
                   at: "2026-09-15T10:00:00Z")
    delegate(@store, delegation_id: "D-LATE", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-C",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-10T00:00:00Z",
             valid_to: "2026-10-01T00:00:00Z")

    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-C",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-20T00:00:00Z",
      policy: default_policy
    )

    refute result.authorized?
    assert_equal "DELEGATION_LATE_ARRIVAL", result.reason_code
    assert_equal ["CONSENT-1", "D-LATE"], result.chain.map(&:id)
    assert result.chain.all?(&:redacted)
  end

  def test_delegation_after_source_expiry_is_source_expired
    delegate(@store, delegation_id: "D-LATE", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-B",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-12-15T00:00:00Z",
             valid_to: "2027-01-01T00:00:00Z")

    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-12-20T00:00:00Z",
      policy: default_policy
    )

    refute result.authorized?
    assert_equal "DELEGATION_SOURCE_EXPIRED", result.reason_code
  end

  def test_source_revoked_at_decision_time_cascades
    delegate(@store, delegation_id: "DELEG-OK", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-B",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-02T00:00:00Z",
             valid_to: "2026-10-01T00:00:00Z")
    revoke_consent(@store, revocation_id: "REV-1", consent_id: "CONSENT-1",
                   at: "2026-09-15T10:00:00Z")

    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-16T00:00:00Z",
      policy: default_policy
    )

    refute result.authorized?
    assert_equal "DELEGATION_SOURCE_REVOKED", result.reason_code
  end

  def test_circular_sub_chain_is_rejected_with_evidence
    delegate(@store, delegation_id: "D1", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-B",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-02T00:00:00Z",
             valid_to: "2026-09-01T00:00:00Z")
    delegate(@store, delegation_id: "D2", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-B", to_sup: "SUPPORTER-C",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-03T00:00:00Z")
    delegate(@store, delegation_id: "D3", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-C", to_sup: "SUPPORTER-B",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-04T00:00:00Z")

    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-10-01T00:00:00Z",
      policy: default_policy
    )

    refute result.authorized?
    assert_equal "DELEGATION_CYCLE", result.reason_code
    refute_empty result.chain
  end

  def test_event_time_filter_future_dated_event_does_not_affect_past_decision
    grant_consent(@store, consent_id: "FUTURE-CONSENT", supporter: "SUPPORTER-X",
                  scopes: ["MEDICAL_INFORMATION_VIEW"],
                  from: "2026-11-01T00:00:00Z", to: "2026-12-01T00:00:00Z",
                  occurred_at: "2026-11-01T00:00:00Z")

    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-X",
      scope: "MEDICAL_INFORMATION_VIEW", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )

    refute result.authorized?
    assert_equal "NO_CONSENT", result.reason_code
  end

  def test_reason_code_is_stable_across_repeated_evaluations
    delegate(@store, delegation_id: "DELEG-BROAD", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-B",
             scopes: ["MEDICAL_INFORMATION_VIEW"],
             occurred_at: "2026-08-02T00:00:00Z")

    codes = 5.times.map do
      @store.evaluate_decision(
        person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
        scope: "MEDICAL_INFORMATION_VIEW", at: "2026-09-01T00:00:00Z",
        policy: default_policy
      ).reason_code
    end

    assert_equal 1, codes.uniq.length
    assert_equal "DELEGATION_BROADER_THAN_SOURCE", codes.first
  end

  def test_rejected_sub_chain_replay_produces_identical_reason_and_chain
    delegate(@store, delegation_id: "LONG-DELEG", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-B",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-02T00:00:00Z",
             valid_to: "2027-06-01T00:00:00Z")

    decision = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )
    assert_equal "DELEGATION_DURATION_EXCEEDS_SOURCE", decision.reason_code

    verify = @store.verify_replay(decision.decision_id)
    assert verify[:reason_code_matches]
    assert verify[:chain_matches]
    assert_equal "DELEGATION_DURATION_EXCEEDS_SOURCE",
                 verify[:recomputed_reason_code]
  end

  def test_chain_evidence_carries_audit_sequences
    delegate(@store, delegation_id: "DELEG-BROAD", source_consent: "CONSENT-1",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-B",
             scopes: ["MEDICAL_INFORMATION_VIEW"],
             occurred_at: "2026-08-02T00:00:00Z")

    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "MEDICAL_INFORMATION_VIEW", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )

    sequences = result.chain.map(&:sequence)
    assert_equal [1, 2], sequences
  end

  def test_witness_requirement_propagates_to_sub_chain
    grant_consent(@store, consent_id: "NO-WITNESS", supporter: "SUPPORTER-A",
                  scopes: ["LEGAL_AID_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z",
                  witness: nil, occurred_at: "2026-08-01T00:00:00Z")
    delegate(@store, delegation_id: "D-NW", source_consent: "NO-WITNESS",
             from_sup: "SUPPORTER-A", to_sup: "SUPPORTER-B",
             scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-02T00:00:00Z")

    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )

    refute result.authorized?
    assert_equal "WITNESS_MISSING", result.reason_code
  end
end
