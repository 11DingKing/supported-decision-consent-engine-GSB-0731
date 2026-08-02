# frozen_string_literal: true

require_relative "test_helper"

# Exercises the pure authorization engine against the authoritative material.
# Every assertion maps to a boundary rule: silence/missing/expired/revoked/
# broader-than-source never grants ordinary authority.
class ConsentEngineTest < Minitest::Test
  include TestSupport

  R = Consent::ReasonCodes

  def setup
    @ledger = seeded_ledger
  end

  def decide(supporter, scope, at)
    @ledger.evaluate(supporter_id: supporter, scope: scope, at: at)
  end

  # --- Direct consent -----------------------------------------------------

  def test_direct_consent_authorizes_within_window
    d = decide("SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-09-01T00:00:00Z")
    assert d.authorized
    assert_equal R::AUTHORIZED_DIRECT_CONSENT, d.reason_code
    assert_equal ["consent"], d.authority_chain.map { |l| l["type"] }
    assert_equal "CONSENT-1", d.authority_chain.first["consentId"]
  end

  def test_scope_outside_consent_is_denied
    # CONSENT-1 covers LEGAL_AID + HOUSING, not MEDICAL. Supporter-A directly.
    d = decide("SUPPORTER-A", "MEDICAL_INFORMATION_VIEW", "2026-09-01T00:00:00Z")
    refute d.authorized
    assert_equal R::SCOPE_NOT_IN_CONSENT, d.reason_code
  end

  def test_unknown_supporter_is_denied
    d = decide("SUPPORTER-Z", "LEGAL_AID_APPLICATION", "2026-09-01T00:00:00Z")
    refute d.authorized
    assert_equal R::UNKNOWN_SUPPORTER, d.reason_code
  end

  def test_unknown_scope_is_denied
    d = decide("SUPPORTER-A", "SOMETHING_ELSE", "2026-09-01T00:00:00Z")
    refute d.authorized
    assert_equal R::UNKNOWN_SCOPE, d.reason_code
  end

  def test_before_effective_window_denied
    d = decide("SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-07-01T00:00:00Z")
    refute d.authorized
    assert_equal R::CONSENT_NOT_YET_EFFECTIVE, d.reason_code
  end

  def test_after_expiry_denied
    # Fresh, un-revoked consent so expiry is the operative cause (in the seed,
    # CONSENT-1 is revoked earlier, which correctly takes precedence).
    l = fresh_ledger
    l.add_supporter("S"); l.define_scope("SC")
    l.grant_consent(id: "C", supporter_id: "S", scopes: ["SC"],
                    from: "2026-01-01T00:00:00Z", to: "2026-06-01T00:00:00Z", witness_id: "W")
    d = l.evaluate(supporter_id: "S", scope: "SC", at: "2026-07-01T00:00:00Z")
    refute d.authorized
    assert_equal R::CONSENT_EXPIRED, d.reason_code
  end

  def test_expiry_boundary_is_exclusive
    l = fresh_ledger
    l.add_supporter("S"); l.define_scope("SC")
    l.grant_consent(id: "C", supporter_id: "S", scopes: ["SC"],
                    from: "2026-01-01T00:00:00Z", to: "2026-06-01T00:00:00Z", witness_id: "W")
    # Exactly at `to` is already expired (window is [from, to)).
    d = l.evaluate(supporter_id: "S", scope: "SC", at: "2026-06-01T00:00:00Z")
    assert_equal R::CONSENT_EXPIRED, d.reason_code
  end

  # --- Witness requirement ------------------------------------------------

  def test_unwitnessed_consent_never_authorizes
    l = fresh_ledger
    l.add_supporter("S"); l.define_scope("SC")
    l.grant_consent(id: "C", supporter_id: "S", scopes: ["SC"],
                    from: "2026-01-01T00:00:00Z", to: "2027-01-01T00:00:00Z",
                    witness_id: nil)
    d = l.evaluate(supporter_id: "S", scope: "SC", at: "2026-06-01T00:00:00Z")
    refute d.authorized
    assert_equal R::CONSENT_NOT_WITNESSED, d.reason_code
  end
end
