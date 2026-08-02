require_relative "test_helper"

class ConsentBoundaryTest < Minitest::Test
  def test_silence_is_not_consent
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A", scopes: ["HOUSING_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z")

    result = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "STRANGER",
      scope: "HOUSING_APPLICATION", at: "2026-09-01T00:00:00Z", policy: default_policy
    )

    refute result.authorized?
    assert_equal "NO_CONSENT", result.reason_code
    assert_empty result.chain
  end

  def test_missing_scope_is_not_consent
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A", scopes: ["HOUSING_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z")

    result = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "A",
      scope: "MEDICAL_INFORMATION_VIEW", at: "2026-09-01T00:00:00Z", policy: default_policy
    )

    refute result.authorized?
    assert_equal "SCOPE_NOT_GRANTED", result.reason_code
  end

  def test_expired_consent_does_not_grant
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A", scopes: ["HOUSING_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-09-01T00:00:00Z")

    result = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "A",
      scope: "HOUSING_APPLICATION", at: "2026-09-02T00:00:00Z", policy: default_policy
    )

    refute result.authorized?
    assert_equal "EXPIRED", result.reason_code
  end

  def test_consent_valid_at_exact_start_boundary
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A", scopes: ["HOUSING_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-09-01T00:00:00Z")

    result = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "A",
      scope: "HOUSING_APPLICATION", at: "2026-08-01T00:00:00Z", policy: default_policy
    )

    assert result.authorized?
    assert_equal "AUTHORIZED", result.reason_code
  end

  def test_consent_expires_at_exact_end_boundary_half_open
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A", scopes: ["HOUSING_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-09-01T00:00:00Z")

    result = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "A",
      scope: "HOUSING_APPLICATION", at: "2026-09-01T00:00:00Z", policy: default_policy
    )

    refute result.authorized?
    assert_equal "EXPIRED", result.reason_code
  end

  def test_not_yet_valid_consent
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A", scopes: ["HOUSING_APPLICATION"],
                  from: "2026-12-01T00:00:00Z", to: "2026-12-31T00:00:00Z")

    result = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "A",
      scope: "HOUSING_APPLICATION", at: "2026-09-01T00:00:00Z", policy: default_policy
    )

    refute result.authorized?
    assert_equal "NOT_YET_VALID", result.reason_code
  end

  def test_consent_without_witness_is_invalid
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A", scopes: ["HOUSING_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z", witness: nil)

    result = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "A",
      scope: "HOUSING_APPLICATION", at: "2026-09-01T00:00:00Z", policy: default_policy
    )

    refute result.authorized?
    assert_equal "WITNESS_MISSING", result.reason_code
  end

  def test_revocation_immediately_invalidates_consent
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A", scopes: ["HOUSING_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z")
    revoke_consent(store, revocation_id: "R1", consent_id: "C1", at: "2026-09-15T10:00:00Z")

    before = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "A",
      scope: "HOUSING_APPLICATION", at: "2026-09-15T09:59:59Z", policy: default_policy
    )
    exact = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "A",
      scope: "HOUSING_APPLICATION", at: "2026-09-15T10:00:00Z", policy: default_policy
    )
    after = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "A",
      scope: "HOUSING_APPLICATION", at: "2026-09-15T10:00:01Z", policy: default_policy
    )

    assert before.authorized?, "decision one second before revocation must be authorized"
    assert_equal "AUTHORIZED", before.reason_code

    refute exact.authorized?, "decision at exact revocation instant must be revoked"
    assert_equal "REVOKED", exact.reason_code

    refute after.authorized?
    assert_equal "REVOKED", after.reason_code
  end

  def test_revocation_cascades_to_delegation
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A",
                  scopes: ["LEGAL_AID_APPLICATION", "HOUSING_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z")
    delegate(store, delegation_id: "D1", source_consent: "C1", from_sup: "A", to_sup: "B",
             scopes: ["LEGAL_AID_APPLICATION"], occurred_at: "2026-08-02T00:00:00Z",
             valid_to: "2026-11-01T00:00:00Z")
    revoke_consent(store, revocation_id: "R1", consent_id: "C1", at: "2026-09-15T10:00:00Z")

    before = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z", policy: default_policy
    )
    after = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-16T00:00:00Z", policy: default_policy
    )

    assert before.authorized?
    assert_equal ["C1", "D1"], before.chain.map(&:id)

    refute after.authorized?
    assert_equal "DELEGATION_SOURCE_REVOKED", after.reason_code
  end

  def test_delegation_broader_than_source_is_rejected
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A",
                  scopes: ["LEGAL_AID_APPLICATION", "HOUSING_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z")
    delegate(store, delegation_id: "DBROAD", source_consent: "C1", from_sup: "A", to_sup: "B",
             scopes: ["MEDICAL_INFORMATION_VIEW"], occurred_at: "2026-08-02T00:00:00Z")

    result = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "B",
      scope: "MEDICAL_INFORMATION_VIEW", at: "2026-09-01T00:00:00Z", policy: default_policy
    )

    refute result.authorized?
    assert_equal "DELEGATION_BROADER_THAN_SOURCE", result.reason_code
    assert_empty result.chain
  end

  def test_multi_level_delegation_narrows_scope
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A",
                  scopes: ["LEGAL_AID_APPLICATION", "HOUSING_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z")
    delegate(store, delegation_id: "D1", source_consent: "C1", from_sup: "A", to_sup: "B",
             scopes: ["LEGAL_AID_APPLICATION"], occurred_at: "2026-08-02T00:00:00Z",
             valid_to: "2026-11-01T00:00:00Z")
    delegate(store, delegation_id: "D2", source_consent: "C1", from_sup: "B", to_sup: "C",
             scopes: ["LEGAL_AID_APPLICATION"], occurred_at: "2026-08-03T00:00:00Z",
             valid_to: "2026-10-01T00:00:00Z")

    result = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "C",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z", policy: default_policy
    )

    assert result.authorized?
    assert_equal ["C1", "D1", "D2"], result.chain.map(&:id)
    assert_equal :delegation, result.chain.last.kind
  end

  def test_delegation_chain_cycle_is_detected
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A",
                  scopes: ["LEGAL_AID_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z")
    delegate(store, delegation_id: "D1", source_consent: "C1", from_sup: "A", to_sup: "B",
             scopes: ["LEGAL_AID_APPLICATION"], occurred_at: "2026-08-02T00:00:00Z",
             valid_to: "2026-09-01T00:00:00Z")
    delegate(store, delegation_id: "D2", source_consent: "C1", from_sup: "B", to_sup: "C",
             scopes: ["LEGAL_AID_APPLICATION"], occurred_at: "2026-08-03T00:00:00Z")
    delegate(store, delegation_id: "D3", source_consent: "C1", from_sup: "C", to_sup: "B",
             scopes: ["LEGAL_AID_APPLICATION"], occurred_at: "2026-08-04T00:00:00Z")

    result = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-10-01T00:00:00Z", policy: default_policy
    )

    refute result.authorized?
    assert_equal "DELEGATION_CYCLE", result.reason_code
  end

  def test_delegation_after_source_expiry_is_invalid
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A",
                  scopes: ["LEGAL_AID_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-09-01T00:00:00Z")
    delegate(store, delegation_id: "DLATE", source_consent: "C1", from_sup: "A", to_sup: "B",
             scopes: ["LEGAL_AID_APPLICATION"], occurred_at: "2026-09-15T00:00:00Z")

    result = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-16T00:00:00Z", policy: default_policy
    )

    refute result.authorized?
    assert_equal "DELEGATION_SOURCE_EXPIRED", result.reason_code
  end

  def test_delegation_without_source_consent
    store = fresh_store
    delegate(store, delegation_id: "DORPHAN", source_consent: "DOES-NOT-EXIST",
             from_sup: "A", to_sup: "B", scopes: ["LEGAL_AID_APPLICATION"],
             occurred_at: "2026-08-02T00:00:00Z")

    result = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z", policy: default_policy
    )

    refute result.authorized?
    assert_equal "DELEGATION_WITHOUT_SOURCE", result.reason_code
  end

  def test_expired_delegation
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A",
                  scopes: ["LEGAL_AID_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z")
    delegate(store, delegation_id: "D1", source_consent: "C1", from_sup: "A", to_sup: "B",
             scopes: ["LEGAL_AID_APPLICATION"], occurred_at: "2026-08-02T00:00:00Z",
             valid_to: "2026-10-01T00:00:00Z")

    result = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-10-02T00:00:00Z", policy: default_policy
    )

    refute result.authorized?
    assert_equal "DELEGATION_EXPIRED", result.reason_code
  end

  def test_emergency_access_authorized_within_window
    store = fresh_store
    start_emergency(store, emergency_id: "E1", scope: "LEGAL_AID_APPLICATION",
                    started_at: "2026-09-01T10:00:00Z", supporter: "ANY")

    result = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "ANY",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T10:15:00Z", policy: default_policy
    )

    assert result.authorized?
    assert_equal "EMERGENCY_AUTHORIZED", result.reason_code
    assert result.emergency
    assert_equal "E1", result.emergency["emergencyId"]
  end

  def test_emergency_access_times_out
    store = fresh_store
    start_emergency(store, emergency_id: "E1", scope: "LEGAL_AID_APPLICATION",
                    started_at: "2026-09-01T10:00:00Z")

    at_deadline = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "ANY",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T10:30:00Z", policy: default_policy
    )
    after = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "ANY",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T10:31:00Z", policy: default_policy
    )

    refute at_deadline.authorized?, "at exact deadline the emergency window is closed (half-open)"
    assert_equal "EMERGENCY_TIMEOUT", at_deadline.reason_code

    refute after.authorized?
    assert_equal "EMERGENCY_TIMEOUT", after.reason_code
  end

  def test_emergency_scope_cannot_expand
    store = fresh_store
    start_emergency(store, emergency_id: "E1", scope: "LEGAL_AID_APPLICATION",
                    started_at: "2026-09-01T10:00:00Z")

    result = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "ANY",
      scope: "MEDICAL_INFORMATION_VIEW", at: "2026-09-01T10:15:00Z", policy: default_policy
    )

    refute result.authorized?
    refute_equal "EMERGENCY_AUTHORIZED", result.reason_code
    assert_nil result.emergency
  end

  def test_emergency_does_not_override_other_scope_denial
    store = fresh_store
    start_emergency(store, emergency_id: "E1", scope: "LEGAL_AID_APPLICATION",
                    started_at: "2026-09-01T10:00:00Z")

    result = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "ANY",
      scope: "HOUSING_APPLICATION", at: "2026-09-01T10:15:00Z", policy: default_policy
    )

    refute result.authorized?
    assert_equal "NO_CONSENT", result.reason_code
  end

  def test_emergency_review_recorded_is_reflected
    store = fresh_store
    start_emergency(store, emergency_id: "E1", scope: "LEGAL_AID_APPLICATION",
                    started_at: "2026-09-01T10:00:00Z")
    review_emergency(store, emergency_id: "E1", reviewed_at: "2026-09-01T10:20:00Z")

    result = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "ANY",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T10:25:00Z", policy: default_policy
    )

    assert result.authorized?
    assert result.emergency["reviewRecorded"]
  end

  def test_delegation_revocation_cuts_authority
    store = fresh_store
    grant_consent(store, consent_id: "C1", supporter: "A",
                  scopes: ["LEGAL_AID_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z")
    delegate(store, delegation_id: "D1", source_consent: "C1", from_sup: "A", to_sup: "B",
             scopes: ["LEGAL_AID_APPLICATION"], occurred_at: "2026-08-02T00:00:00Z",
             valid_to: "2026-11-01T00:00:00Z")
    revoke_delegation(store, revocation_id: "DR1", delegation_id: "D1", at: "2026-09-15T10:00:00Z")

    before = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z", policy: default_policy
    )
    after = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-16T00:00:00Z", policy: default_policy
    )

    assert before.authorized?
    assert_equal ["C1", "D1"], before.chain.map(&:id)
    refute after.authorized?
    assert_equal "REVOKED", after.reason_code
  end

  def test_authoritative_seed_data_reproduces_expected_boundaries
    store = fresh_store
    seed_authoritative(store)

    a_before = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z", policy: default_policy
    )
    assert a_before.authorized?
    assert_equal ["CONSENT-1"], a_before.chain.map(&:id)

    b_before = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z", policy: default_policy
    )
    assert b_before.authorized?
    assert_equal ["CONSENT-1", "DELEG-OK"], b_before.chain.map(&:id)

    b_broad = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "MEDICAL_INFORMATION_VIEW", at: "2026-09-01T00:00:00Z", policy: default_policy
    )
    refute b_broad.authorized?
    assert_equal "DELEGATION_BROADER_THAN_SOURCE", b_broad.reason_code

    a_after_revoke = store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-16T00:00:00Z", policy: default_policy
    )
    refute a_after_revoke.authorized?
    assert_equal "REVOKED", a_after_revoke.reason_code
  end
end
