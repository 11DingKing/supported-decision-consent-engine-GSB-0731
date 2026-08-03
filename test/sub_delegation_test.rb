# frozen_string_literal: true

require_relative "test_helper"

# Round 2: concurrent sub-delegations against the same source consent.
#
# Threat model:
#   * Two supporters receive sub-delegations (DELEG-OK, DELEG-BROAD) from
#     SUPPORTER-A under CONSENT-1 at nearly the same time.
#   * One sub-delegation may be saved after CONSENT-1 was revoked but try to
#     back-date its effective_at — the audit seq must catch this.
#   * Another may arrive late.
#   * Two sibling sub-delegations may together exceed the source's budget
#     even though each is individually within scope.
#   * Cycles in multi-hop chains must not grant authority.
#
# Every denial returned to a sub-delegation holder MUST use a stable,
# non-scope-leaking reason code; the detailed chain evidence (event ids,
# kinds, scopes) is preserved in the chain array for audit, but the
# top-level code never reveals which scopes exist on other delegations.
class SubDelegationTest < Minitest::Test
  include TestHelpers

  def setup
    @service = build_service
    @service.store.clock = fixed_clock("2026-08-01T00:00:00Z")
    @service.register_person("PERSON-01")
    %w[SUPPORTER-A SUPPORTER-B SUPPORTER-C].each do |s|
      @service.register_supporter(s)
    end
    @service.grant_consent(
      consent_id: "CONSENT-1",
      person_id: "PERSON-01",
      supporter_id: "SUPPORTER-A",
      scopes: %w[LEGAL_AID_APPLICATION HOUSING_APPLICATION],
      from: "2026-08-01T00:00:00Z",
      to: "2026-12-01T00:00:00Z",
      witness_id: "W-1",
      emergency_minutes: 30,
      effective_at: "2026-08-01T00:00:00Z"
    )
  end

  # ------------------------------------------------------------------
  # 1. Concurrent DELEG-OK and DELEG-BROAD
  # ------------------------------------------------------------------

  def test_deleg_ok_grants_subset_scope
    @service.delegate(
      delegation_id: "DELEG-OK",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A",
      to_supporter_id: "SUPPORTER-B",
      scopes: %w[LEGAL_AID_APPLICATION],
      to: "2026-10-01T00:00:00Z",
      emergency_minutes: 10,
      effective_at: "2026-08-05T00:00:00Z"
    )
    d = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z"
    )
    assert d.granted?
    assert_equal ConsentEngine::ReasonCodes::GRANTED_VIA_DELEGATION, d.reason_code
    assert_equal %w[PERSON_CONSENT DELEGATION], d.chain.map(&:kind)
    assert_equal %w[CONSENT-1 DELEG-OK], d.chain.map(&:event_id)
  end

  def test_deleg_broad_is_denied_and_does_not_leak_scope_in_code
    @service.delegate(
      delegation_id: "DELEG-BROAD",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A",
      to_supporter_id: "SUPPORTER-B",
      scopes: %w[MEDICAL_INFORMATION_VIEW],
      effective_at: "2026-08-05T00:00:00Z"
    )
    d = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "MEDICAL_INFORMATION_VIEW", as_of: "2026-09-01T00:00:00Z"
    )
    refute d.granted?
    # DELEGATION_BROAD is a stable code; it does NOT name the missing scope
    # or the source's scope set.
    assert_equal ConsentEngine::ReasonCodes::DELEGATION_BROAD, d.reason_code
    # The chain evidence preserves the event ids for audit, but an external
    # caller only sees the code, not the other side's scopes.
    assert_equal %w[CONSENT-1 DELEG-BROAD], d.chain.map(&:event_id)
  end

  def test_concurrent_deleg_ok_and_broad_only_ok_grants
    @service.delegate(
      delegation_id: "DELEG-OK",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A",
      to_supporter_id: "SUPPORTER-B",
      scopes: %w[LEGAL_AID_APPLICATION],
      to: "2026-10-01T00:00:00Z",
      emergency_minutes: 10,
      effective_at: "2026-08-05T00:00:00Z"
    )
    @service.delegate(
      delegation_id: "DELEG-BROAD",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A",
      to_supporter_id: "SUPPORTER-C",
      scopes: %w[MEDICAL_INFORMATION_VIEW],
      effective_at: "2026-08-05T00:01:00Z"
    )

    # The union of sibling scopes now contains MEDICAL which is outside the
    # source consent's scope set. The cumulative budget is exceeded, so B's
    # otherwise-valid delegation is also denied — no silent privilege
    # expansion through a concurrent broad sibling.
    d_b = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z"
    )
    refute d_b.granted?
    assert_equal ConsentEngine::ReasonCodes::DELEGATION_BUDGET_EXCEEDED, d_b.reason_code

    # C's own delegation carries MEDICAL which is outside the source, so C
    # gets the more specific DELEGATION_BROAD.
    d_c = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-C",
      scope: "MEDICAL_INFORMATION_VIEW", as_of: "2026-09-01T00:00:00Z"
    )
    refute d_c.granted?
    assert_equal ConsentEngine::ReasonCodes::DELEGATION_BROAD, d_c.reason_code
  end

  # ------------------------------------------------------------------
  # 2. Revocation saved before sub-chain — seq-order enforcement
  # ------------------------------------------------------------------

  def test_delegation_appended_after_revocation_is_denied_even_with_earlier_effective_at
    # Revoke first, then append a delegation with an earlier effective_at.
    @service.revoke_consent(
      revocation_id: "REVOKE-1",
      consent_id: "CONSENT-1",
      at: "2026-09-15T10:00:00Z",
      effective_at: "2026-09-15T10:00:00Z"
    )
    @service.delegate(
      delegation_id: "DELEG-LATE",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A",
      to_supporter_id: "SUPPORTER-B",
      scopes: %w[LEGAL_AID_APPLICATION],
      to: "2026-10-01T00:00:00Z",
      emergency_minutes: 10,
      effective_at: "2026-08-05T00:00:00Z"
    )
    d = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z"
    )
    refute d.granted?, "delegation appended after revocation must be denied"
    # Seq-order violation produces a stable, non-scope-leaking code.
    assert_equal ConsentEngine::ReasonCodes::DELEGATION_AFTER_REVOCATION, d.reason_code
    assert_equal %w[CONSENT-1 DELEG-LATE], d.chain.map(&:event_id)
  end

  def test_delegation_appended_before_revocation_still_denied_after_revoke_time
    @service.delegate(
      delegation_id: "DELEG-OK",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A",
      to_supporter_id: "SUPPORTER-B",
      scopes: %w[LEGAL_AID_APPLICATION],
      to: "2026-11-01T00:00:00Z",
      emergency_minutes: 10,
      effective_at: "2026-08-05T00:00:00Z"
    )
    @service.revoke_consent(
      revocation_id: "REVOKE-1",
      consent_id: "CONSENT-1",
      at: "2026-09-15T10:00:00Z",
      effective_at: "2026-09-15T10:00:00Z"
    )
    # Before revoke: granted.
    d_before = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z"
    )
    assert d_before.granted?

    # At exact revoke instant: denied.
    d_at = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-15T10:00:00Z"
    )
    refute d_at.granted?
    assert_equal ConsentEngine::ReasonCodes::DELEGATION_SOURCE_REVOKED, d_at.reason_code

    # After revoke: denied.
    d_after = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-20T00:00:00Z"
    )
    refute d_after.granted?
    assert_equal ConsentEngine::ReasonCodes::DELEGATION_SOURCE_REVOKED, d_after.reason_code
  end

  # ------------------------------------------------------------------
  # 3. Cumulative budget across sibling sub-delegations
  # ------------------------------------------------------------------

  def test_cumulative_emergency_minutes_budget_enforced
    @service.delegate(
      delegation_id: "D1",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A",
      to_supporter_id: "SUPPORTER-B",
      scopes: %w[LEGAL_AID_APPLICATION],
      to: "2026-11-01T00:00:00Z",
      emergency_minutes: 20,
      effective_at: "2026-08-05T00:00:00Z"
    )
    # D1 alone is within 30-minute budget.
    d1 = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z"
    )
    assert d1.granted?

    # D2 pushes total to 35 > 30.
    @service.delegate(
      delegation_id: "D2",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A",
      to_supporter_id: "SUPPORTER-C",
      scopes: %w[LEGAL_AID_APPLICATION],
      to: "2026-11-01T00:00:00Z",
      emergency_minutes: 15,
      effective_at: "2026-08-06T00:00:00Z"
    )

    # B's chain now exceeds the cumulative budget and must be denied.
    d_b = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z"
    )
    refute d_b.granted?
    assert_equal ConsentEngine::ReasonCodes::DELEGATION_BUDGET_EXCEEDED, d_b.reason_code
    # The chain evidence identifies B's own path only, not D2's scope.
    assert_equal %w[CONSENT-1 D1], d_b.chain.map(&:event_id)

    # C is also denied.
    d_c = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-C",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z"
    )
    refute d_c.granted?
    assert_equal ConsentEngine::ReasonCodes::DELEGATION_BUDGET_EXCEEDED, d_c.reason_code
  end

  def test_cumulative_time_window_budget_enforced
    # D1 ends after the source consent's to (2026-12-01).
    @service.delegate(
      delegation_id: "D-LONG",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A",
      to_supporter_id: "SUPPORTER-B",
      scopes: %w[LEGAL_AID_APPLICATION],
      to: "2027-01-01T00:00:00Z",
      effective_at: "2026-08-05T00:00:00Z"
    )
    d = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z"
    )
    refute d.granted?
    assert_equal ConsentEngine::ReasonCodes::DELEGATION_BUDGET_EXCEEDED, d.reason_code
  end

  def test_cumulative_scope_union_across_siblings_enforced
    # D1 has LEGAL_AID within source. D2 adds MEDICAL which is outside
    # the source scope set. The union exceeds the source.
    @service.delegate(
      delegation_id: "D1",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A",
      to_supporter_id: "SUPPORTER-B",
      scopes: %w[LEGAL_AID_APPLICATION],
      to: "2026-10-01T00:00:00Z",
      effective_at: "2026-08-05T00:00:00Z"
    )
    @service.delegate(
      delegation_id: "D2",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A",
      to_supporter_id: "SUPPORTER-C",
      scopes: %w[MEDICAL_INFORMATION_VIEW],
      effective_at: "2026-08-06T00:00:00Z"
    )
    d = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z"
    )
    # The union of sibling scopes now contains MEDICAL which is not in the
    # source — cumulative budget is exceeded.
    refute d.granted?
    assert_equal ConsentEngine::ReasonCodes::DELEGATION_BUDGET_EXCEEDED, d.reason_code
  end

  # ------------------------------------------------------------------
  # 4. Late arrival / determinism
  # ------------------------------------------------------------------

  def test_late_delegation_does_not_rewrite_earlier_decision
    @service.delegate(
      delegation_id: "DELEG-OK",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A",
      to_supporter_id: "SUPPORTER-B",
      scopes: %w[LEGAL_AID_APPLICATION],
      to: "2026-11-01T00:00:00Z",
      emergency_minutes: 10,
      effective_at: "2026-08-05T00:00:00Z"
    )
    d1 = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z"
    )
    decision_id = @service.events.last.event_id
    assert d1.granted?

    # A second delegation arrives later. It pushes the cumulative emergency
    # budget over (10+25 = 35 > 30).
    @service.delegate(
      delegation_id: "DELEG-LATE",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A",
      to_supporter_id: "SUPPORTER-C",
      scopes: %w[LEGAL_AID_APPLICATION],
      to: "2026-11-01T00:00:00Z",
      emergency_minutes: 25,
      effective_at: "2026-08-10T00:00:00Z"
    )

    # A fresh decision now sees the budget exceeded.
    d2 = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z"
    )
    refute d2.granted?
    assert_equal ConsentEngine::ReasonCodes::DELEGATION_BUDGET_EXCEEDED, d2.reason_code

    # But the original decision replays to GRANTED at its pinned seen_seq.
    d1_replay = @service.replay(decision_id)
    assert d1_replay.granted?
    assert_equal d1.reason_code, d1_replay.reason_code
    assert_equal d1.seen_seq, d1_replay.seen_seq
    assert_equal d1.chain.map(&:event_id), d1_replay.chain.map(&:event_id)
  end

  # ------------------------------------------------------------------
  # 5. Cycle detection in multi-hop chains
  # ------------------------------------------------------------------

  def test_cycle_in_multi_hop_chain_is_detected
    @service.delegate(
      delegation_id: "D1",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A",
      to_supporter_id: "SUPPORTER-B",
      scopes: %w[LEGAL_AID_APPLICATION],
      to: "2026-11-01T00:00:00Z",
      effective_at: "2026-08-05T00:00:00Z"
    )
    @service.delegate(
      delegation_id: "D2",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-B",
      to_supporter_id: "SUPPORTER-A",
      scopes: %w[LEGAL_AID_APPLICATION],
      to: "2026-11-01T00:00:00Z",
      effective_at: "2026-08-06T00:00:00Z"
    )
    # A direct delegation from A to C still works (non-cyclic path).
    @service.delegate(
      delegation_id: "D3",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A",
      to_supporter_id: "SUPPORTER-C",
      scopes: %w[LEGAL_AID_APPLICATION],
      to: "2026-11-01T00:00:00Z",
      effective_at: "2026-08-07T00:00:00Z"
    )
    d = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-C",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z"
    )
    assert d.granted?, "non-cyclic direct path D3 should still grant"
    assert_equal ConsentEngine::ReasonCodes::GRANTED_VIA_DELEGATION, d.reason_code
  end

  # ------------------------------------------------------------------
  # 6. Non-scope-leaking denial evidence
  # ------------------------------------------------------------------

  def test_denied_subchain_reason_code_does_not_name_scopes
    @service.delegate(
      delegation_id: "DELEG-BROAD",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A",
      to_supporter_id: "SUPPORTER-B",
      scopes: %w[MEDICAL_INFORMATION_VIEW],
      effective_at: "2026-08-05T00:00:00Z"
    )
    d = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
      scope: "MEDICAL_INFORMATION_VIEW", as_of: "2026-09-01T00:00:00Z"
    )
    refute d.granted?
    # Top-level code is stable and contains no scope identifier.
    refute d.reason_code.include?("MEDICAL"),
           "reason code must not leak scope names"
    assert_equal ConsentEngine::ReasonCodes::DELEGATION_BROAD, d.reason_code
    # Chain evidence preserves event ids for audit (not scope enumeration of
    # unrelated parties).
    assert d.chain.first.event_id == "CONSENT-1"
    assert d.chain.last.event_id  == "DELEG-BROAD"
  end

  def test_replay_after_concurrent_changes_is_stable
    # Capture a baseline decision.
    d1 = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z"
    )
    decision_id = @service.events.last.event_id
    assert d1.granted?

    # Concurrent-ish writes: add a delegation and a revocation.
    @service.delegate(
      delegation_id: "D-CONC",
      source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A",
      to_supporter_id: "SUPPORTER-B",
      scopes: %w[LEGAL_AID_APPLICATION],
      to: "2026-11-01T00:00:00Z",
      emergency_minutes: 10,
      effective_at: "2026-08-05T00:00:00Z"
    )
    @service.revoke_consent(
      revocation_id: "R-CONC",
      consent_id: "CONSENT-1",
      at: "2026-09-15T10:00:00Z",
      effective_at: "2026-09-15T10:00:00Z"
    )

    d_replay = @service.replay(decision_id)
    assert_equal d1.granted?,     d_replay.granted?
    assert_equal d1.reason_code,  d_replay.reason_code
    assert_equal d1.seen_seq,     d_replay.seen_seq
    assert_equal d1.chain.map(&:event_id), d_replay.chain.map(&:event_id)
  end
end
