# frozen_string_literal: true

require_relative "test_helper"

# THREAT MODEL: Delegation / re-delegation.
#
# Danger: a supporter re-delegates authority they never had (scope creep), or
# keeps delegated authority alive after the SOURCE consent expired/was revoked,
# or a delegation cycle is used to manufacture authority from nothing. Defence:
# delegated authority is only valid if the full upstream chain is independently
# valid as-of the same instant; a delegation can never widen scope beyond its
# source; cycles are detected and denied.
class DelegationTest < Minitest::Test
  include TestSupport

  R = Consent::ReasonCodes

  def setup
    @ledger = seeded_ledger
  end

  def decide(supporter, scope, at)
    @ledger.evaluate(supporter_id: supporter, scope: scope, at: at)
  end

  def test_valid_delegation_authorizes_with_full_chain
    # DELEG-OK: A -> B for LEGAL_AID, sourced from CONSENT-1.
    d = decide("SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-09-01T00:00:00Z")
    assert d.authorized
    assert_equal R::AUTHORIZED_DELEGATED_CONSENT, d.reason_code
    assert_equal %w[consent delegation], d.authority_chain.map { |l| l["type"] }
    assert_equal "CONSENT-1", d.authority_chain.first["consentId"]
    assert_equal "DELEG-OK", d.authority_chain.last["delegationId"]
  end

  def test_delegation_broader_than_source_denied
    # DELEG-BROAD: A -> B for MEDICAL, but CONSENT-1 never covered MEDICAL.
    d = decide("SUPPORTER-B", "MEDICAL_INFORMATION_VIEW", "2026-09-01T00:00:00Z")
    refute d.authorized
    assert_equal R::DELEGATION_SCOPE_EXCEEDS_SOURCE, d.reason_code
  end

  def test_delegation_after_source_revoked_denied
    # After CONSENT-1 is revoked (09-15), the delegated authority collapses too.
    d = decide("SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-09-20T00:00:00Z")
    refute d.authorized
    assert_equal R::SOURCE_CONSENT_INVALID, d.reason_code
  end

  def test_delegation_after_source_expiry_denied
    l = fresh_ledger
    l.add_supporter("A"); l.add_supporter("B"); l.define_scope("S")
    # Source consent expires 2026-06-01.
    l.grant_consent(id: "C", supporter_id: "A", scopes: ["S"],
                    from: "2026-01-01T00:00:00Z", to: "2026-06-01T00:00:00Z", witness_id: "W")
    # Delegation extends further, but cannot outlive its dead source.
    l.create_delegation(id: "D", source_consent_id: "C", from_supporter_id: "A",
                        to_supporter_id: "B", scopes: ["S"], to: "2026-12-01T00:00:00Z")
    d = l.evaluate(supporter_id: "B", scope: "S", at: "2026-08-01T00:00:00Z")
    refute d.authorized
    assert_equal R::SOURCE_CONSENT_INVALID, d.reason_code
  end

  def test_multi_level_delegation_chain
    l = fresh_ledger
    %w[A B C].each { |s| l.add_supporter(s) }
    l.define_scope("S")
    l.grant_consent(id: "C1", supporter_id: "A", scopes: ["S"],
                    from: "2026-01-01T00:00:00Z", to: "2027-01-01T00:00:00Z", witness_id: "W")
    l.create_delegation(id: "D1", source_consent_id: "C1", from_supporter_id: "A",
                        to_supporter_id: "B", scopes: ["S"])
    l.create_delegation(id: "D2", source_consent_id: "C1", from_supporter_id: "B",
                        to_supporter_id: "C", scopes: ["S"])
    d = l.evaluate(supporter_id: "C", scope: "S", at: "2026-06-01T00:00:00Z")
    assert d.authorized
    assert_equal R::AUTHORIZED_DELEGATED_CONSENT, d.reason_code
    assert_equal %w[consent delegation delegation], d.authority_chain.map { |x| x["type"] }
  end

  def test_multi_level_chain_breaks_when_root_revoked
    l = fresh_ledger
    %w[A B C].each { |s| l.add_supporter(s) }
    l.define_scope("S")
    l.grant_consent(id: "C1", supporter_id: "A", scopes: ["S"],
                    from: "2026-01-01T00:00:00Z", to: "2027-01-01T00:00:00Z", witness_id: "W")
    l.create_delegation(id: "D1", source_consent_id: "C1", from_supporter_id: "A",
                        to_supporter_id: "B", scopes: ["S"])
    l.create_delegation(id: "D2", source_consent_id: "C1", from_supporter_id: "B",
                        to_supporter_id: "C", scopes: ["S"])
    l.revoke_consent(consent_id: "C1", at: "2026-05-01T00:00:00Z")
    d = l.evaluate(supporter_id: "C", scope: "S", at: "2026-06-01T00:00:00Z")
    refute d.authorized
    assert_equal R::SOURCE_CONSENT_INVALID, d.reason_code
  end

  def test_delegation_cycle_denied
    # P -> Q -> P with no independent root consent for either: pure cycle.
    l = fresh_ledger
    l.add_supporter("P"); l.add_supporter("Q"); l.define_scope("S")
    l.grant_consent(id: "C1", supporter_id: "ROOT", scopes: ["S"],
                    from: "2026-01-01T00:00:00Z", to: "2027-01-01T00:00:00Z", witness_id: "W")
    l.add_supporter("ROOT")
    l.create_delegation(id: "D1", source_consent_id: "C1", from_supporter_id: "P",
                        to_supporter_id: "Q", scopes: ["S"])
    l.create_delegation(id: "D2", source_consent_id: "C1", from_supporter_id: "Q",
                        to_supporter_id: "P", scopes: ["S"])
    d = l.evaluate(supporter_id: "Q", scope: "S", at: "2026-06-01T00:00:00Z")
    refute d.authorized
    assert_equal R::DELEGATION_CYCLE, d.reason_code
  end

  def test_expired_delegation_link_denied
    l = fresh_ledger
    l.add_supporter("A"); l.add_supporter("B"); l.define_scope("S")
    l.grant_consent(id: "C1", supporter_id: "A", scopes: ["S"],
                    from: "2026-01-01T00:00:00Z", to: "2027-01-01T00:00:00Z", witness_id: "W")
    l.create_delegation(id: "D1", source_consent_id: "C1", from_supporter_id: "A",
                        to_supporter_id: "B", scopes: ["S"], to: "2026-06-01T00:00:00Z")
    d = l.evaluate(supporter_id: "B", scope: "S", at: "2026-08-01T00:00:00Z")
    refute d.authorized
    assert_equal R::DELEGATION_EXPIRED, d.reason_code
  end
end
