# frozen_string_literal: true

require_relative "test_helper"
require "domain"

# Pure domain tests: no database, no HTTP. Facts mirror
# materials/consent-cases.json unless a test overrides them.
class DomainTest < Minitest::Test
  T = ->(s) { Time.iso8601(s) }

  FROM = T.call("2026-08-01T00:00:00Z")
  TO = T.call("2026-12-01T00:00:00Z")
  REVOKE_AT = T.call("2026-09-15T10:00:00Z")

  def base_consent(overrides = {})
    Domain::Consent.new({ id: "CONSENT-1", person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
                          scopes: %w[LEGAL_AID_APPLICATION HOUSING_APPLICATION],
                          valid_from: FROM, valid_to: TO, witness_id: "W-1" }.merge(overrides))
  end

  def world(consents: [base_consent], delegations: [], revocations: [], emergencies: [],
            policies: { "PERSON-01" => Domain::EmergencyPolicy.new(allowed_scope: "LEGAL_AID_APPLICATION", max_minutes: 30, requires_review_event: true) })
    Domain::World.new(persons: ["PERSON-01"], supporters: %w[SUPPORTER-A SUPPORTER-B SUPPORTER-C SUPPORTER-D],
                      consents: consents, delegations: delegations, revocations: revocations,
                      emergencies: emergencies, emergency_policies: policies, as_of_seq: 99)
  end

  def eval(w, supporter, scope, at)
    Domain::Authorizer.evaluate(world: w, supporter_id: supporter, scope: scope, at: T.call(at))
  end

  # --- silence / missing / expired / revoked never grant -------------------

  def test_silence_is_not_consent
    d = eval(world, "SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-08-10T00:00:00Z")
    assert_equal "DENY_NO_CONSENT", d.reason_code
    refute d.authorized?
  end

  def test_missing_scope_is_not_consent
    d = eval(world, "SUPPORTER-A", "MEDICAL_INFORMATION_VIEW", "2026-08-10T00:00:00Z")
    assert_equal "DENY_SCOPE_NOT_COVERED", d.reason_code
    refute d.authorized?
  end

  def test_direct_ok_with_witness_in_chain
    d = eval(world, "SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-08-10T00:00:00Z")
    assert_equal "OK_DIRECT", d.reason_code
    assert d.authorized?
    assert_equal "W-1", d.chain.first["witnessId"]
  end

  def test_valid_from_boundary_is_active
    d = eval(world, "SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-08-01T00:00:00Z")
    assert_equal "OK_DIRECT", d.reason_code
  end

  def test_valid_to_boundary_is_expired
    d = eval(world, "SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-12-01T00:00:00Z")
    assert_equal "DENY_CONSENT_EXPIRED", d.reason_code
    refute d.authorized?
  end

  def revoked_world
    world(revocations: [Domain::Revocation.new(id: "REVOKE-1", consent_id: "CONSENT-1", at: REVOKE_AT)])
  end

  def test_revoked_consent_denies_after_revocation
    d = eval(revoked_world, "SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-09-16T00:00:00Z")
    assert_equal "DENY_CONSENT_REVOKED", d.reason_code
    assert_equal "2026-09-15T10:00:00Z", d.chain.first["revokedAt"]
  end

  def test_consent_still_active_before_revocation
    d = eval(revoked_world, "SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-09-14T00:00:00Z")
    assert_equal "OK_DIRECT", d.reason_code
  end

  # Threat: an in-flight decision landing exactly on the revocation instant.
  # Fail-closed tie-break: the revocation has already taken effect.
  def test_decision_at_exact_revocation_instant_is_revoked
    d = eval(revoked_world, "SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-09-15T10:00:00Z")
    assert_equal "DENY_CONSENT_REVOKED", d.reason_code
    refute d.authorized?
  end

  def test_one_second_before_revocation_instant_is_ok
    d = eval(revoked_world, "SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-09-15T09:59:59Z")
    assert_equal "OK_DIRECT", d.reason_code
  end

  # --- delegation ----------------------------------------------------------

  def deleg_ok
    Domain::Delegation.new(id: "DELEG-OK", source_consent_id: "CONSENT-1",
                           from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                           scopes: ["LEGAL_AID_APPLICATION"], effective_from: FROM,
                           valid_to: T.call("2026-10-01T00:00:00Z"), created_seq: 5)
  end

  def test_delegated_ok_with_full_chain
    d = eval(world(delegations: [deleg_ok]), "SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-08-15T00:00:00Z")
    assert_equal "OK_DELEGATED", d.reason_code
    assert d.authorized?
    assert_equal %w[consent delegation], d.chain.map { |l| l["type"] }
    assert_equal "CONSENT-1", d.chain[0]["id"]
    assert_equal "DELEG-OK", d.chain[1]["id"]
  end

  def test_delegation_does_not_cover_scope_outside_its_own_list
    d = eval(world(delegations: [deleg_ok]), "SUPPORTER-B", "HOUSING_APPLICATION", "2026-08-15T00:00:00Z")
    assert_equal "DENY_DELEGATION_SCOPE", d.reason_code
    refute d.authorized?
  end

  # Threat: a delegation broader than its source somehow persisted (write-time
  # validation bypassed). Evaluation still refuses it — defense in depth.
  def test_broader_than_source_delegation_never_grants_even_if_persisted
    broad = Domain::Delegation.new(id: "DELEG-BROAD", source_consent_id: "CONSENT-1",
                                   from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                                   scopes: ["MEDICAL_INFORMATION_VIEW"], effective_from: FROM,
                                   valid_to: nil, created_seq: 6)
    d = eval(world(delegations: [broad]), "SUPPORTER-B", "MEDICAL_INFORMATION_VIEW", "2026-08-15T00:00:00Z")
    assert_equal "DENY_DELEGATION_SCOPE", d.reason_code
    refute d.authorized?
  end

  def test_delegation_after_source_revocation_is_denied_at_evaluation
    w = world(delegations: [deleg_ok],
              revocations: [Domain::Revocation.new(id: "R", consent_id: "CONSENT-1", at: REVOKE_AT)])
    d = eval(w, "SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-09-16T00:00:00Z")
    assert_equal "DENY_DELEGATION_SOURCE_REVOKED", d.reason_code
  end

  def test_delegation_after_source_expiry_is_denied_at_evaluation
    open_ended = Domain::Delegation.new(id: "D-OPEN", source_consent_id: "CONSENT-1",
                                        from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                                        scopes: ["LEGAL_AID_APPLICATION"], effective_from: FROM,
                                        valid_to: nil, created_seq: 6)
    d = eval(world(delegations: [open_ended]), "SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-12-02T00:00:00Z")
    assert_equal "DENY_DELEGATION_SOURCE_EXPIRED", d.reason_code
  end

  def test_delegation_past_its_own_valid_to_is_denied
    d = eval(world(delegations: [deleg_ok]), "SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-10-02T00:00:00Z")
    assert_equal "DENY_DELEGATION_EXPIRED", d.reason_code
  end

  def multi_level
    [deleg_ok,
     Domain::Delegation.new(id: "DELEG-L2", source_consent_id: "CONSENT-1",
                            from_supporter_id: "SUPPORTER-B", to_supporter_id: "SUPPORTER-C",
                            scopes: ["LEGAL_AID_APPLICATION"], effective_from: FROM,
                            valid_to: T.call("2026-09-01T00:00:00Z"), created_seq: 6)]
  end

  def test_multi_level_delegation_chain
    d = eval(world(delegations: multi_level), "SUPPORTER-C", "LEGAL_AID_APPLICATION", "2026-08-20T00:00:00Z")
    assert_equal "OK_DELEGATED", d.reason_code
    assert_equal ["CONSENT-1", "DELEG-OK", "DELEG-L2"], d.chain.map { |l| l["id"] }
  end

  def test_multi_level_breaks_when_middle_link_expires
    d = eval(world(delegations: multi_level), "SUPPORTER-C", "LEGAL_AID_APPLICATION", "2026-09-02T00:00:00Z")
    assert_equal "DENY_DELEGATION_EXPIRED", d.reason_code
  end

  # Threat: cycles through multiple delegations must terminate and deny, not
  # loop forever or silently grant.
  def test_cycle_through_multiple_delegations_denies
    cyclic = [
      Domain::Delegation.new(id: "D1", source_consent_id: "CONSENT-1", from_supporter_id: "SUPPORTER-C",
                             to_supporter_id: "SUPPORTER-D", scopes: ["LEGAL_AID_APPLICATION"],
                             effective_from: FROM, valid_to: nil, created_seq: 7),
      Domain::Delegation.new(id: "D2", source_consent_id: "CONSENT-1", from_supporter_id: "SUPPORTER-D",
                             to_supporter_id: "SUPPORTER-C", scopes: ["LEGAL_AID_APPLICATION"],
                             effective_from: FROM, valid_to: nil, created_seq: 8)
    ]
    d = eval(world(delegations: cyclic), "SUPPORTER-D", "LEGAL_AID_APPLICATION", "2026-08-20T00:00:00Z")
    assert_equal "DENY_DELEGATION_CYCLE", d.reason_code
    refute d.authorized?
  end

  def test_write_time_cycle_detection
    w = world(delegations: multi_level)
    assert w.delegation_would_cycle?("SUPPORTER-C", "SUPPORTER-A")
    refute w.delegation_would_cycle?("SUPPORTER-C", "SUPPORTER-D")
  end

  # --- write-time validation ----------------------------------------------

  def test_validate_delegation_broader_than_source
    err = Domain::Validate.delegation(world: world, source_consent_id: "CONSENT-1",
                                      from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                                      scopes: ["MEDICAL_INFORMATION_VIEW"],
                                      effective_from: FROM, valid_to: nil)
    assert_equal "DELEGATION_BROADER_THAN_SOURCE", err
  end

  def test_validate_delegation_after_source_expiry
    err = Domain::Validate.delegation(world: world, source_consent_id: "CONSENT-1",
                                      from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                                      scopes: ["LEGAL_AID_APPLICATION"],
                                      effective_from: T.call("2026-12-02T00:00:00Z"), valid_to: nil)
    assert_equal "DELEGATION_SOURCE_EXPIRED", err
  end

  def test_validate_delegation_after_source_revocation
    err = Domain::Validate.delegation(world: revoked_world, source_consent_id: "CONSENT-1",
                                      from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                                      scopes: ["LEGAL_AID_APPLICATION"],
                                      effective_from: T.call("2026-09-16T00:00:00Z"), valid_to: nil)
    assert_equal "DELEGATION_SOURCE_REVOKED", err
  end

  def test_validate_delegation_cannot_outlive_source
    err = Domain::Validate.delegation(world: world, source_consent_id: "CONSENT-1",
                                      from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                                      scopes: ["LEGAL_AID_APPLICATION"],
                                      effective_from: FROM, valid_to: T.call("2027-01-01T00:00:00Z"))
    assert_equal "DELEGATION_WINDOW_INVALID", err
  end

  def test_validate_consent_requires_witness
    err = Domain::Validate.consent(world: world, person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
                                   scopes: ["LEGAL_AID_APPLICATION"], valid_from: FROM, valid_to: TO,
                                   witness_id: nil)
    assert_equal "WITNESS_REQUIRED", err
  end

  # --- emergency exception --------------------------------------------------

  def episode(reviewed_at: nil)
    Domain::EmergencyEpisode.new(id: "EMG-1", supporter_id: "SUPPORTER-B", scope: "LEGAL_AID_APPLICATION",
                                 started_at: T.call("2026-08-10T10:00:00Z"), max_minutes: 30,
                                 reviewed_at: reviewed_at)
  end

  def test_emergency_within_window_reviewed
    d = eval(world(emergencies: [episode(reviewed_at: T.call("2026-08-10T10:20:00Z"))]),
             "SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-08-10T10:15:00Z")
    assert_equal "OK_EMERGENCY", d.reason_code
    assert d.authorized?
  end

  def test_emergency_within_window_review_pending
    d = eval(world(emergencies: [episode]), "SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-08-10T10:15:00Z")
    assert_equal "OK_EMERGENCY_REVIEW_PENDING", d.reason_code
    assert d.authorized?
    assert_equal "within_window_review_pending", d.chain.first["status"]
  end

  def test_emergency_exactly_at_window_end_still_valid
    d = eval(world(emergencies: [episode]), "SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-08-10T10:30:00Z")
    assert_equal "OK_EMERGENCY_REVIEW_PENDING", d.reason_code
  end

  # Threat: emergency exception used past its 30-minute window must time out.
  def test_emergency_timeout_denies
    d = eval(world(emergencies: [episode]), "SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-08-10T10:31:00Z")
    assert_equal "DENY_EMERGENCY_TIMEOUT", d.reason_code
    refute d.authorized?
  end

  def test_emergency_never_covers_other_scopes
    d = eval(world(emergencies: [episode]), "SUPPORTER-B", "HOUSING_APPLICATION", "2026-08-10T10:15:00Z")
    assert_equal "DENY_NO_CONSENT", d.reason_code
  end

  # --- determinism ------------------------------------------------------------

  def test_evaluation_is_deterministic
    w = world(delegations: multi_level, revocations: [Domain::Revocation.new(id: "R", consent_id: "CONSENT-1", at: REVOKE_AT)])
    a = Domain::Authorizer.evaluate(world: w, supporter_id: "SUPPORTER-C", scope: "LEGAL_AID_APPLICATION", at: T.call("2026-08-20T00:00:00Z"))
    b = Domain::Authorizer.evaluate(world: w, supporter_id: "SUPPORTER-C", scope: "LEGAL_AID_APPLICATION", at: T.call("2026-08-20T00:00:00Z"))
    assert_equal a.reason_code, b.reason_code
    assert_equal a.chain, b.chain
  end
end
