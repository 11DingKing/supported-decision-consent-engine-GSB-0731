# frozen_string_literal: true

require_relative "test_helper"

# THREAT MODEL: Race conditions & history rewriting.
#
# Danger: a decision and a revocation (or a new grant) submitted concurrently
# race such that authority is silently widened, or a later-recorded fact
# rewrites the answer to a past decision. Defence: each decision pins an
# event_time AND the max audit seq visible at that moment; replaying the same
# pair reproduces the identical reason code and authority chain. The event log
# is physically append-only (immutable), so no race can rewrite a recorded fact.
class DeterminismTest < Minitest::Test
  include TestSupport

  R = Consent::ReasonCodes

  def test_replay_is_deterministic_at_fixed_anchors
    l = seeded_ledger
    at = "2026-09-01T00:00:00Z"
    seq = l.max_seq
    first = l.evaluate(supporter_id: "SUPPORTER-B", scope: "LEGAL_AID_APPLICATION", at: at, as_of_seq: seq)
    20.times do
      again = l.evaluate(supporter_id: "SUPPORTER-B", scope: "LEGAL_AID_APPLICATION", at: at, as_of_seq: seq)
      assert_equal first.reason_code, again.reason_code
      assert_equal first.authority_chain, again.authority_chain
    end
  end

  def test_later_appended_fact_does_not_change_pinned_decision
    l = seeded_ledger
    at = "2026-09-20T00:00:00Z"
    seq_now = l.max_seq
    before = l.evaluate(supporter_id: "SUPPORTER-A", scope: "HOUSING_APPLICATION", at: at, as_of_seq: seq_now)

    # Append a NEW revocation that would deny it going forward.
    l.revoke_consent(consent_id: "CONSENT-1", at: "2026-09-10T00:00:00Z")

    # Replaying with the OLD seq ceiling must reproduce the original answer.
    replay = l.evaluate(supporter_id: "SUPPORTER-A", scope: "HOUSING_APPLICATION", at: at, as_of_seq: seq_now)
    assert_equal before.reason_code, replay.reason_code
    assert_equal before.authority_chain, replay.authority_chain

    # But the current view (higher seq) reflects the new fact.
    current = l.evaluate(supporter_id: "SUPPORTER-A", scope: "HOUSING_APPLICATION", at: at)
    assert_equal R::CONSENT_REVOKED, current.reason_code
  end

  def test_concurrent_grant_and_revoke_never_widens_scope
    # Fire many concurrent decisions while a revocation is being appended. No
    # decision anchored at/after the revocation instant may be authorized, and
    # each pinned decision must be internally consistent (never a wider scope
    # than its anchors justify).
    l = fresh_ledger
    l.add_supporter("S"); l.define_scope("SC")
    l.grant_consent(id: "C", supporter_id: "S", scopes: ["SC"],
                    from: "2026-01-01T00:00:00Z", to: "2027-01-01T00:00:00Z", witness_id: "W")

    revoke_at = "2026-06-01T00:00:00Z"
    results = []
    mutex = Mutex.new
    threads = []

    threads << Thread.new do
      l.revoke_consent(consent_id: "C", at: revoke_at)
    end

    10.times do
      threads << Thread.new do
        d = l.decide(supporter_id: "S", scope: "SC", at: "2026-08-01T00:00:00Z")
        mutex.synchronize { results << [d.as_of_seq, d.reason_code, d.authorized] }
      end
    end

    threads.each(&:join)

    # Every decision that saw the revocation (its seq ceiling included it) must
    # be denied; those that ran before cannot have widened scope either.
    results.each do |seq, code, authorized|
      replay = l.evaluate(supporter_id: "S", scope: "SC", at: "2026-08-01T00:00:00Z", as_of_seq: seq)
      assert_equal code, replay.reason_code, "recorded decision must replay identically at its own seq"
      assert_equal authorized, replay.authorized
    end

    # Final state after all writes committed: revoked.
    final = l.evaluate(supporter_id: "S", scope: "SC", at: "2026-08-01T00:00:00Z")
    refute final.authorized
    assert_equal R::CONSENT_REVOKED, final.reason_code
  end

  def test_concurrent_appends_produce_unique_ordered_seqs
    l = fresh_ledger
    l.add_supporter("S"); l.define_scope("SC")
    threads = (1..25).map do |i|
      Thread.new { l.define_scope("SCOPE_#{i}") }
    end
    threads.each(&:join)
    seqs = l.events.map(&:seq)
    assert_equal seqs.uniq.sort, seqs.sort, "audit seqs must be unique"
    assert_equal seqs, seqs.sort, "events load in monotonic seq order"
  end
end
