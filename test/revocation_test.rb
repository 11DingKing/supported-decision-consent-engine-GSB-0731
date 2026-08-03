# frozen_string_literal: true

require_relative "test_helper"

# THREAT MODEL: Revocation.
#
# Danger: the system treats silence or an in-flight decision as continued
# consent, so a supporter keeps acting after the person withdrew. Defence: a
# revocation is monotonic and takes effect AT its instant (t >= revoked_at =>
# revoked), checked before expiry, and a decision landing exactly on the
# revocation instant is denied — never a coin flip.
class RevocationTest < Minitest::Test
  include TestSupport

  R = Consent::ReasonCodes

  def setup
    @ledger = seeded_ledger # REVOKE-1 revokes CONSENT-1 at 2026-09-15T10:00:00Z
  end

  def decide(supporter, scope, at, as_of_seq: nil)
    @ledger.evaluate(supporter_id: supporter, scope: scope, at: at, as_of_seq: as_of_seq)
  end

  def test_just_before_revocation_still_authorized
    d = decide("SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-09-15T09:59:59Z")
    assert d.authorized
    assert_equal R::AUTHORIZED_DIRECT_CONSENT, d.reason_code
  end

  def test_decision_at_exact_revocation_instant_is_revoked
    d = decide("SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-09-15T10:00:00Z")
    refute d.authorized, "in-flight decision at the exact revocation instant must not slip through"
    assert_equal R::CONSENT_REVOKED, d.reason_code
  end

  def test_after_revocation_is_revoked
    d = decide("SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-09-16T00:00:00Z")
    refute d.authorized
    assert_equal R::CONSENT_REVOKED, d.reason_code
  end

  def test_revocation_takes_precedence_over_expiry
    # Even if we ask after the natural expiry, an earlier revocation is the
    # reported cause because revocation is checked first (more specific).
    d = decide("SUPPORTER-A", "LEGAL_AID_APPLICATION", "2027-01-01T00:00:00Z")
    assert_equal R::CONSENT_REVOKED, d.reason_code
  end

  def test_revocation_is_monotonic_cannot_be_loosened
    # A second, later "revocation" event can never move the effective instant
    # forward: the earliest revocation wins.
    l = fresh_ledger
    l.add_supporter("S"); l.define_scope("SC")
    l.grant_consent(id: "C", supporter_id: "S", scopes: ["SC"],
                    from: "2026-01-01T00:00:00Z", to: "2027-01-01T00:00:00Z", witness_id: "W")
    l.revoke_consent(consent_id: "C", at: "2026-06-01T00:00:00Z")
    l.revoke_consent(consent_id: "C", at: "2026-08-01T00:00:00Z")
    d = l.evaluate(supporter_id: "S", scope: "SC", at: "2026-07-01T00:00:00Z")
    refute d.authorized
    assert_equal R::CONSENT_REVOKED, d.reason_code
  end

  def test_replay_before_revocation_seq_ignores_later_revocation
    # Pin the audit ceiling to before the revocation was recorded: the replay
    # must reproduce the pre-revocation answer, proving history isn't rewritten.
    seq_before_revocation = find_seq_before("CONSENT_REVOKED")
    d = decide("SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-09-20T00:00:00Z",
               as_of_seq: seq_before_revocation)
    assert d.authorized, "at an earlier audit seq the revocation is not yet visible"
    assert_equal R::AUTHORIZED_DIRECT_CONSENT, d.reason_code
  end

  private

  def find_seq_before(type)
    ev = @ledger.events.find { |e| e.type == type }
    ev.seq - 1
  end
end
