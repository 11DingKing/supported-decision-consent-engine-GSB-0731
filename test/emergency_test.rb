# frozen_string_literal: true

require_relative "test_helper"

# Threat model: EMERGENCY EXCEPTION.
#
# The risk: an emergency carve-out is used as a permanent backdoor, its scope
# bleeds outside the single allowed matter, or it persists after the timeout.
#
# Invariants under test:
#   * Emergency grants only the configured allowed_scope.
#   * Authority expires after max_minutes.
#   * When requires_review_event is true, a missing review event means DENIED.
#   * A recorded review event within the window grants.
#   * After the window, even with review, the emergency grant is TIMEOUT.
#   * Emergency cannot be combined with an unrelated scope to broaden authority.
class EmergencyTest < Minitest::Test
  include TestHelpers

  EMERGENCY_CFG = {
    allowed_scope: "LEGAL_AID_APPLICATION",
    max_minutes: 30,
    requires_review_event: true
  }.freeze

  def setup
    @service = build_service(emergency: EMERGENCY_CFG)
    @service.store.clock = fixed_clock("2026-08-01T00:00:00Z")
    @service.register_person("P1")
    @service.register_supporter("S1")
  end

  def test_emergency_grants_only_within_window_and_scope
    @service.activate_emergency(
      event_id: "EM1", person_id: "P1", supporter_id: "S1",
      effective_at: "2026-09-01T10:00:00Z"
    )
    @service.record_emergency_review(
      event_id: "RV1", person_id: "P1",
      effective_at: "2026-09-01T10:05:00Z"
    )

    d = @service.decide(
      person_id: "P1", supporter_id: "S1",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T10:10:00Z"
    )
    assert d.granted?
    assert_equal ConsentEngine::ReasonCodes::GRANTED_EMERGENCY, d.reason_code
    assert_equal "EMERGENCY", d.chain.first.kind
  end

  def test_emergency_denied_outside_scope
    @service.activate_emergency(
      event_id: "EM1", person_id: "P1", supporter_id: "S1",
      effective_at: "2026-09-01T10:00:00Z"
    )
    @service.record_emergency_review(
      event_id: "RV1", person_id: "P1",
      effective_at: "2026-09-01T10:05:00Z"
    )
    d = @service.decide(
      person_id: "P1", supporter_id: "S1",
      scope: "MEDICAL_INFORMATION_VIEW", as_of: "2026-09-01T10:10:00Z"
    )
    refute d.granted?
    assert_equal ConsentEngine::ReasonCodes::EMERGENCY_SCOPE_NOT_ALLOWED, d.reason_code
  end

  def test_emergency_timeout
    @service.activate_emergency(
      event_id: "EM1", person_id: "P1", supporter_id: "S1",
      effective_at: "2026-09-01T10:00:00Z"
    )
    @service.record_emergency_review(
      event_id: "RV1", person_id: "P1",
      effective_at: "2026-09-01T10:05:00Z"
    )
    d = @service.decide(
      person_id: "P1", supporter_id: "S1",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T10:31:00Z"
    )
    refute d.granted?
    assert_equal ConsentEngine::ReasonCodes::EMERGENCY_TIMEOUT, d.reason_code
  end

  def test_emergency_denied_without_review_event
    @service.activate_emergency(
      event_id: "EM1", person_id: "P1", supporter_id: "S1",
      effective_at: "2026-09-01T10:00:00Z"
    )
    d = @service.decide(
      person_id: "P1", supporter_id: "S1",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T10:10:00Z"
    )
    refute d.granted?
    assert_equal ConsentEngine::ReasonCodes::EMERGENCY_WITHOUT_REVIEW_EVENT, d.reason_code
  end

  def test_emergency_at_exact_window_end_is_denied
    @service.activate_emergency(
      event_id: "EM1", person_id: "P1", supporter_id: "S1",
      effective_at: "2026-09-01T10:00:00Z"
    )
    @service.record_emergency_review(
      event_id: "RV1", person_id: "P1",
      effective_at: "2026-09-01T10:05:00Z"
    )
    d = @service.decide(
      person_id: "P1", supporter_id: "S1",
      scope: "LEGAL_AID_APPLICATION", as_of: "2026-09-01T10:30:00Z"
    )
    refute d.granted?, "at exactly max_minutes the window is closed (half-open)"
    assert_equal ConsentEngine::ReasonCodes::EMERGENCY_TIMEOUT, d.reason_code
  end
end
