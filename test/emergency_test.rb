# frozen_string_literal: true

require_relative "test_helper"

# THREAT MODEL: Emergency exception.
#
# Danger: a time-boxed emergency override outlives its window (timeout ignored),
# is used for a scope it was never meant for, skips a required review, or is
# treated as delegatable. Defence: emergency is a last-resort fallback only
# when ordinary authority failed; it is scope-restricted, hard-expires at
# invoked_at + maxMinutes, requires a recorded review when policy demands it,
# and is never delegatable.
class EmergencyTest < Minitest::Test
  include TestSupport

  R = Consent::ReasonCodes

  def build_ledger(requires_review:, reviewed: false)
    l = fresh_ledger
    l.add_supporter("S"); l.define_scope("LEGAL_AID_APPLICATION"); l.define_scope("MEDICAL_INFORMATION_VIEW")
    l.set_emergency_policy(allowed_scope: "LEGAL_AID_APPLICATION", max_minutes: 30,
                           requires_review_event: requires_review)
    l.invoke_emergency(id: "E1", supporter_id: "S", scope: "LEGAL_AID_APPLICATION",
                       at: "2026-06-01T12:00:00Z", max_minutes: 30)
    l.review_emergency(emergency_id: "E1", at: "2026-06-01T12:10:00Z") if reviewed
    l
  end

  def test_emergency_authorizes_within_window_when_no_review_required
    l = build_ledger(requires_review: false)
    d = l.evaluate(supporter_id: "S", scope: "LEGAL_AID_APPLICATION", at: "2026-06-01T12:15:00Z")
    assert d.authorized
    assert_equal R::AUTHORIZED_EMERGENCY, d.reason_code
    assert_equal ["emergency"], d.authority_chain.map { |x| x["type"] }
  end

  def test_emergency_expires_at_timeout_boundary
    l = build_ledger(requires_review: false)
    # invoked 12:00 + 30min = 12:30 deadline (exclusive).
    d = l.evaluate(supporter_id: "S", scope: "LEGAL_AID_APPLICATION", at: "2026-06-01T12:30:00Z")
    refute d.authorized, "emergency must hard-expire at the timeout boundary"
    assert_equal R::EMERGENCY_EXPIRED, d.reason_code
  end

  def test_emergency_past_timeout_denied
    l = build_ledger(requires_review: false)
    d = l.evaluate(supporter_id: "S", scope: "LEGAL_AID_APPLICATION", at: "2026-06-01T13:00:00Z")
    refute d.authorized
    assert_equal R::EMERGENCY_EXPIRED, d.reason_code
  end

  def test_emergency_scope_restriction
    l = build_ledger(requires_review: false)
    # Invoke for a scope outside the policy's allowed scope.
    l.invoke_emergency(id: "E2", supporter_id: "S", scope: "MEDICAL_INFORMATION_VIEW",
                       at: "2026-06-01T12:00:00Z", max_minutes: 30)
    d = l.evaluate(supporter_id: "S", scope: "MEDICAL_INFORMATION_VIEW", at: "2026-06-01T12:15:00Z")
    refute d.authorized
    assert_equal R::EMERGENCY_SCOPE_NOT_ALLOWED, d.reason_code
  end

  def test_required_review_missing_denies
    l = build_ledger(requires_review: true, reviewed: false)
    d = l.evaluate(supporter_id: "S", scope: "LEGAL_AID_APPLICATION", at: "2026-06-01T12:15:00Z")
    refute d.authorized, "silence about the mandated review is not authority"
    assert_equal R::EMERGENCY_REVIEW_MISSING, d.reason_code
  end

  def test_required_review_present_authorizes
    l = build_ledger(requires_review: true, reviewed: true)
    d = l.evaluate(supporter_id: "S", scope: "LEGAL_AID_APPLICATION", at: "2026-06-01T12:15:00Z")
    assert d.authorized
    assert_equal R::AUTHORIZED_EMERGENCY, d.reason_code
  end

  def test_emergency_is_not_delegatable
    # Even with an emergency granted to S, delegating from S confers nothing:
    # the source path for T finds no ordinary authority, so the chain fails.
    l = build_ledger(requires_review: false)
    l.add_supporter("T")
    l.grant_consent(id: "CX", supporter_id: "NOBODY", scopes: ["LEGAL_AID_APPLICATION"],
                    from: "2026-01-01T00:00:00Z", to: "2027-01-01T00:00:00Z", witness_id: "W")
    l.add_supporter("NOBODY")
    l.create_delegation(id: "D", source_consent_id: "CX", from_supporter_id: "S",
                        to_supporter_id: "T", scopes: ["LEGAL_AID_APPLICATION"])
    d = l.evaluate(supporter_id: "T", scope: "LEGAL_AID_APPLICATION", at: "2026-06-01T12:15:00Z")
    refute d.authorized, "an emergency grant must never flow through delegation"
    refute_equal R::AUTHORIZED_EMERGENCY, d.reason_code
    refute_equal R::AUTHORIZED_DELEGATED_CONSENT, d.reason_code
  end

  def test_emergency_only_when_ordinary_authority_absent
    # A valid ordinary consent must be preferred and reported, not the emergency.
    l = build_ledger(requires_review: false)
    l.grant_consent(id: "C-ORD", supporter_id: "S", scopes: ["LEGAL_AID_APPLICATION"],
                    from: "2026-01-01T00:00:00Z", to: "2027-01-01T00:00:00Z", witness_id: "W")
    d = l.evaluate(supporter_id: "S", scope: "LEGAL_AID_APPLICATION", at: "2026-06-01T12:15:00Z")
    assert d.authorized
    assert_equal R::AUTHORIZED_DIRECT_CONSENT, d.reason_code
  end
end
