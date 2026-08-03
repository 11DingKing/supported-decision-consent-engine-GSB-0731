# frozen_string_literal: true

require_relative "test_helper"
require "domain"
require "json"

# Sub-delegation rules, reusing the round-1 identifiers from
# materials/consent-cases.json: CONSENT-1 (SUPPORTER-A, scopes
# LEGAL_AID_APPLICATION + HOUSING_APPLICATION, witness W-1), the person-level
# emergency policy (LEGAL_AID_APPLICATION, 30 minutes).
class SubDelegationTest < Minitest::Test
  T = ->(s) { Time.iso8601(s) }

  FROM = T.call("2026-08-01T00:00:00Z")
  TO = T.call("2026-12-01T00:00:00Z")
  REVOKE_AT = T.call("2026-09-15T10:00:00Z")
  POLICY = Domain::EmergencyPolicy.new(allowed_scope: "LEGAL_AID_APPLICATION", max_minutes: 30, requires_review_event: true)

  def consent(budget: nil)
    Domain::Consent.new(id: "CONSENT-1", person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
                        scopes: %w[LEGAL_AID_APPLICATION HOUSING_APPLICATION],
                        valid_from: FROM, valid_to: TO, witness_id: "W-1",
                        emergency_budget_minutes: budget)
  end

  def delegation(id:, from:, to:, scopes:, effective_from: FROM, valid_to: nil, seq: 5, budget: nil)
    Domain::Delegation.new(id: id, source_consent_id: "CONSENT-1", from_supporter_id: from,
                           to_supporter_id: to, scopes: scopes, effective_from: effective_from,
                           valid_to: valid_to, created_seq: seq, emergency_budget_minutes: budget)
  end

  def world(consents: [consent], delegations: [], revocations: [], emergencies: [])
    Domain::World.new(persons: ["PERSON-01"], supporters: %w[SUPPORTER-A SUPPORTER-B SUPPORTER-C SUPPORTER-D],
                      consents: consents, delegations: delegations, revocations: revocations,
                      emergencies: emergencies, emergency_policies: { "PERSON-01" => POLICY }, as_of_seq: 99)
  end

  def eval(w, supporter, scope, at)
    Domain::Authorizer.evaluate(world: w, supporter_id: supporter, scope: scope, at: T.call(at))
  end

  def validate(w, from:, to:, scopes:, at: FROM, valid_to: nil, budget: nil)
    Domain::Validate.delegation(world: w, source_consent_id: "CONSENT-1", from_supporter_id: from,
                                to_supporter_id: to, scopes: scopes, effective_from: at,
                                valid_to: valid_to, emergency_budget_minutes: budget)
  end

  # --- scope / duration / budget never exceed the source --------------------

  def test_subdelegation_within_source_bounds_is_valid
    assert_nil validate(world, from: "SUPPORTER-A", to: "SUPPORTER-B",
                        scopes: ["LEGAL_AID_APPLICATION"], valid_to: T.call("2026-10-01T00:00:00Z"), budget: 20)
  end

  def test_subdelegation_budget_equal_to_source_is_valid
    assert_nil validate(world, from: "SUPPORTER-A", to: "SUPPORTER-B", scopes: ["LEGAL_AID_APPLICATION"], budget: 30)
  end

  def test_subdelegation_budget_over_source_is_rejected
    assert_equal "DELEGATION_BUDGET_EXCEEDED",
                 validate(world, from: "SUPPORTER-A", to: "SUPPORTER-B", scopes: ["LEGAL_AID_APPLICATION"], budget: 31)
  end

  def test_subdelegation_scope_broader_than_source_is_rejected
    assert_equal "DELEGATION_BROADER_THAN_SOURCE",
                 validate(world, from: "SUPPORTER-A", to: "SUPPORTER-B", scopes: ["MEDICAL_INFORMATION_VIEW"])
  end

  def test_subdelegation_duration_beyond_source_is_rejected
    assert_equal "DELEGATION_WINDOW_INVALID",
                 validate(world, from: "SUPPORTER-A", to: "SUPPORTER-B",
                          scopes: ["LEGAL_AID_APPLICATION"], valid_to: T.call("2027-01-01T00:00:00Z"))
  end

  # Threat: two sibling sub-chains each look affordable alone but cumulatively
  # over-allocate the source budget (20 + 20 > 30).
  def test_two_sibling_subchains_cumulative_over_allocation
    w = world(delegations: [delegation(id: "DELEG-OK", from: "SUPPORTER-A", to: "SUPPORTER-B",
                                       scopes: ["LEGAL_AID_APPLICATION"], budget: 20)])
    assert_equal "DELEGATION_BUDGET_EXCEEDED",
                 validate(w, from: "SUPPORTER-A", to: "SUPPORTER-C", scopes: ["LEGAL_AID_APPLICATION"], budget: 20)
    assert_nil validate(w, from: "SUPPORTER-A", to: "SUPPORTER-C", scopes: ["LEGAL_AID_APPLICATION"], budget: 10)
  end

  # Same cumulative rule one level down: B holds 20, so 12 + 12 over-allocates.
  def test_multilevel_subchains_cumulative_over_allocation
    first = delegation(id: "DELEG-OK", from: "SUPPORTER-A", to: "SUPPORTER-B", scopes: ["LEGAL_AID_APPLICATION"], budget: 20)
    w1 = world(delegations: [first])
    assert_nil validate(w1, from: "SUPPORTER-B", to: "SUPPORTER-C", scopes: ["LEGAL_AID_APPLICATION"], budget: 12)

    second = delegation(id: "DELEG-L2", from: "SUPPORTER-B", to: "SUPPORTER-C", scopes: ["LEGAL_AID_APPLICATION"], seq: 6, budget: 12)
    w2 = world(delegations: [first, second])
    assert_equal "DELEGATION_BUDGET_EXCEEDED",
                 validate(w2, from: "SUPPORTER-B", to: "SUPPORTER-D", scopes: ["LEGAL_AID_APPLICATION"], budget: 12)
  end

  # A sub-chain's valid_to is bounded by its parent link, not only by the root.
  def test_subdelegation_window_bounded_by_parent_link
    w = world(delegations: [delegation(id: "DELEG-OK", from: "SUPPORTER-A", to: "SUPPORTER-B",
                                       scopes: ["LEGAL_AID_APPLICATION"], valid_to: T.call("2026-10-01T00:00:00Z"))])
    assert_equal "DELEGATION_WINDOW_INVALID",
                 validate(w, from: "SUPPORTER-B", to: "SUPPORTER-C",
                          scopes: ["LEGAL_AID_APPLICATION"], valid_to: T.call("2026-11-01T00:00:00Z"))
    assert_nil validate(w, from: "SUPPORTER-B", to: "SUPPORTER-C",
                        scopes: ["LEGAL_AID_APPLICATION"], valid_to: T.call("2026-09-30T00:00:00Z"))
  end

  # --- dead source / cycle detection -----------------------------------------

  def test_subdelegation_from_revoked_source_is_rejected
    w = world(revocations: [Domain::Revocation.new(id: "REVOKE-1", consent_id: "CONSENT-1", at: REVOKE_AT)])
    assert_equal "DELEGATION_SOURCE_REVOKED",
                 validate(w, from: "SUPPORTER-A", to: "SUPPORTER-B", scopes: ["LEGAL_AID_APPLICATION"],
                          at: T.call("2026-09-16T00:00:00Z"))
  end

  def test_subdelegation_whose_sender_link_is_not_live_yet_is_rejected
    w = world(delegations: [delegation(id: "DELEG-FUTURE", from: "SUPPORTER-A", to: "SUPPORTER-B",
                                       scopes: ["LEGAL_AID_APPLICATION"], effective_from: T.call("2026-09-01T00:00:00Z"))])
    assert_equal "DELEGATION_NOT_HELD_BY_SENDER",
                 validate(w, from: "SUPPORTER-B", to: "SUPPORTER-C", scopes: ["LEGAL_AID_APPLICATION"],
                          at: T.call("2026-08-15T00:00:00Z"))
  end

  def test_subdelegation_cycle_is_rejected
    w = world(delegations: [delegation(id: "DELEG-OK", from: "SUPPORTER-A", to: "SUPPORTER-B",
                                       scopes: ["LEGAL_AID_APPLICATION"])])
    assert_equal "DELEGATION_CYCLE",
                 validate(w, from: "SUPPORTER-B", to: "SUPPORTER-A", scopes: ["LEGAL_AID_APPLICATION"])
  end

  # --- emergency budget cap at evaluation -------------------------------------

  def episode(started = "2026-08-10T10:00:00Z")
    Domain::EmergencyEpisode.new(id: "EMG-1", supporter_id: "SUPPORTER-B", scope: "LEGAL_AID_APPLICATION",
                                 started_at: T.call(started), max_minutes: 30, reviewed_at: nil)
  end

  # The budget rides a delegation for ANOTHER scope: the supporter has no
  # ordinary authority over the emergency scope, so the exception path runs
  # and the chain's minutes cap applies.
  def budgeted_world(budget: 20)
    world(delegations: [delegation(id: "DELEG-OK", from: "SUPPORTER-A", to: "SUPPORTER-B",
                                   scopes: ["HOUSING_APPLICATION"], budget: budget)],
          emergencies: [episode])
  end

  def test_emergency_within_delegated_budget_is_authorized
    d = eval(budgeted_world, "SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-08-10T10:15:00Z")
    assert_equal "OK_EMERGENCY_REVIEW_PENDING", d.reason_code
    assert_equal 20, d.chain.first["budgetCapMinutes"]
  end

  # Threat: the emergency exception may not burn more minutes than the source
  # budget granted along the chain, even while the policy window is still open.
  def test_emergency_beyond_delegated_budget_is_denied
    d = eval(budgeted_world, "SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-08-10T10:25:00Z")
    assert_equal "DENY_EMERGENCY_BUDGET_EXCEEDED", d.reason_code
    refute d.authorized?
  end

  def test_emergency_beyond_policy_window_still_times_out
    d = eval(budgeted_world, "SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-08-10T10:31:00Z")
    assert_equal "DENY_EMERGENCY_TIMEOUT", d.reason_code
  end

  def test_emergency_without_budget_authority_falls_back_to_policy
    w = world(emergencies: [episode])
    d = eval(w, "SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-08-10T10:25:00Z")
    assert_equal "OK_EMERGENCY_REVIEW_PENDING", d.reason_code
  end

  def test_emergency_budget_min_is_enforced_along_multilevel_chain
    w = world(delegations: [
                delegation(id: "DELEG-OK", from: "SUPPORTER-A", to: "SUPPORTER-B", scopes: ["HOUSING_APPLICATION"], budget: 20),
                delegation(id: "DELEG-L2", from: "SUPPORTER-B", to: "SUPPORTER-C", scopes: ["HOUSING_APPLICATION"], seq: 6, budget: 12)
              ], emergencies: [Domain::EmergencyEpisode.new(id: "EMG-2", supporter_id: "SUPPORTER-C",
                                                            scope: "LEGAL_AID_APPLICATION",
                                                            started_at: T.call("2026-08-10T10:00:00Z"),
                                                            max_minutes: 30, reviewed_at: nil)])
    assert_equal "OK_EMERGENCY_REVIEW_PENDING", eval(w, "SUPPORTER-C", "LEGAL_AID_APPLICATION", "2026-08-10T10:10:00Z").reason_code
    assert_equal "DENY_EMERGENCY_BUDGET_EXCEEDED", eval(w, "SUPPORTER-C", "LEGAL_AID_APPLICATION", "2026-08-10T10:13:00Z").reason_code
  end

  # --- denial evidence: stable and scope-redacted ------------------------------

  def test_denial_chain_redacts_scopes_but_keeps_structure
    w = world(delegations: [delegation(id: "DELEG-OK", from: "SUPPORTER-A", to: "SUPPORTER-B",
                                       scopes: ["LEGAL_AID_APPLICATION"])])
    d = eval(w, "SUPPORTER-B", "MEDICAL_INFORMATION_VIEW", "2026-08-15T00:00:00Z")
    assert_equal "DENY_DELEGATION_SCOPE", d.reason_code
    refute d.chain.empty?
    d.chain.each do |link|
      refute link.key?("scopes"), "denial chain leaks scope contents: #{link}"
      assert link.key?("scopeCount")
      assert link.key?("id")
      assert link.key?("status")
    end
    refute_includes JSON.generate(d.chain), "LEGAL_AID_APPLICATION"
  end

  def test_authorized_chain_keeps_scopes
    w = world(delegations: [delegation(id: "DELEG-OK", from: "SUPPORTER-A", to: "SUPPORTER-B",
                                       scopes: ["LEGAL_AID_APPLICATION"])])
    d = eval(w, "SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-08-15T00:00:00Z")
    assert_equal "OK_DELEGATED", d.reason_code
    assert_equal ["LEGAL_AID_APPLICATION"], d.chain[1]["scopes"]
  end

  def test_rejection_evidence_is_stable_and_redacted
    w = world
    reason = validate(w, from: "SUPPORTER-A", to: "SUPPORTER-B", scopes: ["MEDICAL_INFORMATION_VIEW"])
    a = Domain::Evidence.delegation_rejection(world: w, source_consent_id: "CONSENT-1",
                                              from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                                              attempted_id: "DELEG-BROAD", at: FROM, reason: reason)
    b = Domain::Evidence.delegation_rejection(world: w, source_consent_id: "CONSENT-1",
                                              from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                                              attempted_id: "DELEG-BROAD", at: FROM, reason: reason)
    assert_equal a, b
    assert_equal "rejected", a.last["status"]
    assert_equal "DELEGATION_BROADER_THAN_SOURCE", a.last["reason"]
    assert_equal "DELEG-BROAD", a.last["id"]
    json = JSON.generate(a)
    refute_includes json, "MEDICAL_INFORMATION_VIEW"
    refute_includes json, "LEGAL_AID_APPLICATION"
    assert_equal "W-1", a.first["witnessId"]
  end

  # --- late-arriving sub-chain: validity splits by event time -------------------

  # A sub-chain logged AFTER the revocation (higher audit seq) but effective
  # BEFORE it (earlier event time) is valid only up to the revocation instant.
  def test_late_arriving_subchain_splits_by_event_time
    w = world(delegations: [delegation(id: "DELEG-LATE", from: "SUPPORTER-A", to: "SUPPORTER-B",
                                       scopes: ["LEGAL_AID_APPLICATION"],
                                       effective_from: T.call("2026-09-14T00:00:00Z"), seq: 9)],
              revocations: [Domain::Revocation.new(id: "REVOKE-1", consent_id: "CONSENT-1", at: REVOKE_AT)])
    before = eval(w, "SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-09-14T12:00:00Z")
    assert_equal "OK_DELEGATED", before.reason_code
    assert_equal "DELEG-LATE", before.chain[1]["id"]

    after = eval(w, "SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-09-15T11:00:00Z")
    assert_equal "DENY_DELEGATION_SOURCE_REVOKED", after.reason_code
  end
end
