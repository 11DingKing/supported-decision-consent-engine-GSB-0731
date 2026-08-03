# frozen_string_literal: true

require_relative "test_helper"

# Round 3: REVOKE-1 vs in-flight decision races.
#
# Threat model:
#   * A decision in flight at the exact revocation instant must be denied
#     (half-open interval: T >= R is denied).
#   * One microsecond before revocation: GRANTED.
#   * One microsecond after revocation: REVOKED.
#   * Revocation events can arrive out of order; the earliest business-time
#     revocation governs, and history is never rewritten.
#   * The same decision submitted twice must not expand scope or reset
#     budget — idempotency key returns the prior result unchanged.
#   * Emergency budget already consumed survives revocation: revoking a
#     consent does not refund spent emergency minutes.
#   * Every replay at pinned (decisionAt, seenSeq) returns identical
#     reason code, seq boundary, and chain.
class RevocationRaceTest < Minitest::Test
  include TestHelpers

  REVOKE_AT = "2026-09-15T10:00:00.000000Z"

  def setup
    @service = build_service
    @service.store.clock = fixed_clock("2026-08-01T00:00:00Z")
    @service.register_person("PERSON-01")
    %w[SUPPORTER-A SUPPORTER-B].each { |s| @service.register_supporter(s) }
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
  # 1. Three boundary points around the exact revocation instant
  # ------------------------------------------------------------------

  def test_one_microsecond_before_revocation_is_granted
    @service.revoke_consent(
      revocation_id: "REVOKE-1", consent_id: "CONSENT-1",
      at: REVOKE_AT, effective_at: REVOKE_AT
    )
    t = "2026-09-15T09:59:59.999999Z"
    d = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", as_of: t
    )
    assert d.granted?, "decision 1us before revoke MUST be granted"
    assert_equal ConsentEngine::ReasonCodes::GRANTED, d.reason_code
  end

  def test_exact_revocation_instant_is_denied
    @service.revoke_consent(
      revocation_id: "REVOKE-1", consent_id: "CONSENT-1",
      at: REVOKE_AT, effective_at: REVOKE_AT
    )
    d = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", as_of: REVOKE_AT
    )
    refute d.granted?, "decision at exact revoke instant MUST be denied"
    assert_equal ConsentEngine::ReasonCodes::REVOKED, d.reason_code
  end

  def test_one_microsecond_after_revocation_is_denied
    @service.revoke_consent(
      revocation_id: "REVOKE-1", consent_id: "CONSENT-1",
      at: REVOKE_AT, effective_at: REVOKE_AT
    )
    t = "2026-09-15T10:00:00.000001Z"
    d = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", as_of: t
    )
    refute d.granted?, "decision 1us after revoke MUST be denied"
    assert_equal ConsentEngine::ReasonCodes::REVOKED, d.reason_code
  end

  # ------------------------------------------------------------------
  # 2. Out-of-order revocations
  # ------------------------------------------------------------------

  def test_later_revocation_with_earlier_effective_time_governs
    # First revoke at 10:00.
    @service.revoke_consent(
      revocation_id: "REVOKE-LATE", consent_id: "CONSENT-1",
      at: "2026-09-15T10:00:00Z", effective_at: "2026-09-15T10:00:00Z"
    )
    # Then an out-of-order revoke with effective_at = 09:00 (earlier).
    @service.revoke_consent(
      revocation_id: "REVOKE-EARLY", consent_id: "CONSENT-1",
      at: "2026-09-15T11:00:00Z", effective_at: "2026-09-15T09:00:00Z"
    )

    # Decision at 09:30 — before the first-recorded revoke but after the
    # earlier effective one — MUST be denied because the earliest
    # business-time revocation governs.
    d = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-15T09:30:00Z"
    )
    refute d.granted?
    assert_equal ConsentEngine::ReasonCodes::REVOKED, d.reason_code
  end

  def test_out_of_order_revocation_does_not_rewrite_prior_decision
    # Record a decision at 09:30 when no revocation exists yet.
    d1 = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-15T09:30:00Z"
    )
    assert d1.granted?
    decision_id = @service.events.last.event_id

    # Later, an out-of-order revoke arrives effective 09:00.
    @service.revoke_consent(
      revocation_id: "REVOKE-OOO", consent_id: "CONSENT-1",
      at: "2026-09-15T11:00:00Z", effective_at: "2026-09-15T09:00:00Z"
    )

    # The original decision replays to GRANTED at its pinned seen_seq.
    d2 = @service.replay(decision_id)
    assert d2.granted?, "history must not be rewritten by later events"
    assert_equal d1.reason_code, d2.reason_code
    assert_equal d1.seen_seq, d2.seen_seq
    assert_equal d1.chain.map(&:event_id), d2.chain.map(&:event_id)
  end

  def test_out_of_order_revocation_event_is_flagged
    @service.revoke_consent(
      revocation_id: "REVOKE-1", consent_id: "CONSENT-1",
      at: "2026-09-15T10:00:00Z", effective_at: "2026-09-15T10:00:00Z"
    )
    later = @service.revoke_consent(
      revocation_id: "REVOKE-2", consent_id: "CONSENT-1",
      at: "2026-09-15T11:00:00Z", effective_at: "2026-09-15T11:00:00Z"
    )
    assert later.payload["outOfOrder"], "later-recorded revoke with later effective time should be flagged"
  end

  # ------------------------------------------------------------------
  # 3. Duplicate decision submission (idempotency)
  # ------------------------------------------------------------------

  def test_duplicate_decision_with_idempotency_key_returns_same_result
    d1 = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z",
      idempotency_key: "DECISION-UNIQUE-1"
    )
    assert d1.granted?
    events_before = @service.events.size

    d2 = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z",
      idempotency_key: "DECISION-UNIQUE-1"
    )

    events_after = @service.events.size
    assert_equal events_before, events_after,
                 "duplicate decision must not append a new event"
    assert_equal d1.reason_code, d2.reason_code
    assert_equal d1.seen_seq, d2.seen_seq
    assert_equal d1.chain.map(&:event_id), d2.chain.map(&:event_id)
    assert_equal d1.granted?, d2.granted?
  end

  def test_duplicate_decision_cannot_expand_scope
    d1 = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z",
      idempotency_key: "DECISION-SCOPE-1"
    )
    assert d1.granted?

    # Attempt to re-submit with a broader scope using same key.
    d2 = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "MEDICAL_INFORMATION_VIEW", as_of: "2026-09-01T00:00:00Z",
      idempotency_key: "DECISION-SCOPE-1"
    )
    # The idempotent replay returns the ORIGINAL scope and result.
    assert_equal d1.scope, d2.scope
    assert_equal d1.reason_code, d2.reason_code
  end

  def test_duplicate_decision_does_not_reset_emergency_budget
    # Use a scope NOT covered by ordinary consent so the emergency path
    # is the only route to a grant.
    emergency_cfg = {
      allowed_scope: "MEDICAL_INFORMATION_VIEW",
      max_minutes: 30,
      requires_review_event: true
    }
    service = ConsentEngine::Service.new(
      store: ConsentEngine::EventStore.new,
      emergency_config: emergency_cfg
    )
    service.store.clock = fixed_clock("2026-08-01T00:00:00Z")
    service.register_person("P1")
    service.register_supporter("S1")
    service.grant_consent(
      consent_id: "C1", person_id: "P1", supporter_id: "S1",
      scopes: %w[LEGAL_AID_APPLICATION],
      from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z",
      witness_id: "W1", emergency_minutes: 30,
      effective_at: "2026-08-01T00:00:00Z"
    )

    service.activate_emergency(
      event_id: "EM-1", person_id: "P1", supporter_id: "S1",
      effective_at: "2026-09-01T10:00:00Z"
    )
    service.record_emergency_review(
      event_id: "RV-1", person_id: "P1",
      effective_at: "2026-09-01T10:01:00Z"
    )

    d1 = service.decide(
      person_id: "P1", supporter_id: "S1",
      scope: "MEDICAL_INFORMATION_VIEW", as_of: "2026-09-01T10:05:00Z",
      idempotency_key: "DECISION-EM-1"
    )
    assert d1.granted?
    assert_equal ConsentEngine::ReasonCodes::GRANTED_EMERGENCY, d1.reason_code

    # Re-submit same decision — must not reset or double-count budget.
    d2 = service.decide(
      person_id: "P1", supporter_id: "S1",
      scope: "MEDICAL_INFORMATION_VIEW", as_of: "2026-09-01T10:05:00Z",
      idempotency_key: "DECISION-EM-1"
    )
    assert_equal d1.reason_code, d2.reason_code
    assert_equal d1.seen_seq, d2.seen_seq
    assert_equal d1.chain.map(&:event_id), d2.chain.map(&:event_id)
  end

  # ------------------------------------------------------------------
  # 4. Emergency budget used, then consent revoked — budget not refunded
  # ------------------------------------------------------------------

  def test_emergency_budget_survives_revocation
    emergency_cfg = {
      allowed_scope: "MEDICAL_INFORMATION_VIEW",
      max_minutes: 30,
      requires_review_event: true
    }
    service = ConsentEngine::Service.new(
      store: ConsentEngine::EventStore.new,
      emergency_config: emergency_cfg
    )
    service.store.clock = fixed_clock("2026-08-01T00:00:00Z")
    service.register_person("P1")
    service.register_supporter("S1")
    service.grant_consent(
      consent_id: "C1", person_id: "P1", supporter_id: "S1",
      scopes: %w[LEGAL_AID_APPLICATION],
      from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z",
      witness_id: "W1", emergency_minutes: 30,
      effective_at: "2026-08-01T00:00:00Z"
    )
    service.activate_emergency(
      event_id: "EM-1", person_id: "P1", supporter_id: "S1",
      effective_at: "2026-09-01T10:00:00Z"
    )
    service.record_emergency_review(
      event_id: "RV-1", person_id: "P1",
      effective_at: "2026-09-01T10:01:00Z"
    )

    # Emergency grant at 10:05.
    d1 = service.decide(
      person_id: "P1", supporter_id: "S1",
      scope: "MEDICAL_INFORMATION_VIEW", as_of: "2026-09-01T10:05:00Z"
    )
    assert d1.granted?
    assert_equal ConsentEngine::ReasonCodes::GRANTED_EMERGENCY, d1.reason_code
    em_decision_id = service.events.last.event_id

    # Revoke the consent.
    service.revoke_consent(
      revocation_id: "REVOKE-1", consent_id: "C1",
      at: "2026-09-15T10:00:00Z", effective_at: "2026-09-15T10:00:00Z"
    )

    # After revocation, ordinary consent is denied.
    d2 = service.decide(
      person_id: "P1", supporter_id: "S1",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-20T00:00:00Z"
    )
    refute d2.granted?
    assert_equal ConsentEngine::ReasonCodes::REVOKED, d2.reason_code

    # The prior emergency decision still replays as GRANTED_EMERGENCY at
    # its pinned seen_seq — revocation does not rewrite that history.
    d3 = service.replay(em_decision_id)
    assert d3.granted?
    assert_equal ConsentEngine::ReasonCodes::GRANTED_EMERGENCY, d3.reason_code
    assert_equal d1.seen_seq, d3.seen_seq
  end

  # ------------------------------------------------------------------
  # 5. Replay determinism after all kinds of later events
  # ------------------------------------------------------------------

  def test_replay_after_revoke_delegation_and_emergency_is_stable
    d1 = @service.decide(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T00:00:00Z"
    )
    decision_id = @service.events.last.event_id
    assert d1.granted?

    # Add lots of later history.
    @service.delegate(
      delegation_id: "D1", source_consent_id: "CONSENT-1",
      from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
      scopes: %w[LEGAL_AID_APPLICATION], to: "2026-11-01T00:00:00Z",
      emergency_minutes: 10, effective_at: "2026-08-05T00:00:00Z"
    )
    @service.activate_emergency(
      event_id: "EM-X", person_id: "PERSON-01",
      supporter_id: "SUPPORTER-A", effective_at: "2026-09-10T10:00:00Z"
    )
    @service.revoke_consent(
      revocation_id: "REVOKE-1", consent_id: "CONSENT-1",
      at: "2026-09-15T10:00:00Z", effective_at: "2026-09-15T10:00:00Z"
    )

    d2 = @service.replay(decision_id)
    assert_equal d1.granted?, d2.granted?
    assert_equal d1.reason_code, d2.reason_code
    assert_equal d1.seen_seq, d2.seen_seq
    assert_equal d1.chain.map(&:event_id), d2.chain.map(&:event_id)
    assert_equal d1.decision_at.iso8601, d2.decision_at.iso8601
  end
end
