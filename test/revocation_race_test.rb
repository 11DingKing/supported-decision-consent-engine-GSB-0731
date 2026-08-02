# frozen_string_literal: true

require_relative "test_helper"

# THREAT MODEL (round 3): REVOKE-1 vs. an in-flight decision, at microsecond
# resolution, plus duplicate submission and emergency-budget consumption.
#
# Danger: a decision in flight when a revocation lands is treated as still
# authorized (silence = yes); the microsecond boundary is rounded away so the
# t-1µs / t / t+1µs cases blur; a resubmitted decision appends a fresh fact that
# widens scope or shifts the audit boundary; a duplicated consumption drains or
# RESETS an emergency budget; or revoking an emergency retroactively erases the
# minutes already spent.
#
# Defence: revocation takes effect AT its instant (t >= revoked_at), checked
# before expiry; instants keep microsecond precision so the three boundary cases
# are distinct, reproducible facts. Recording is idempotent by request id — a
# resubmission reproduces the original reason code, authority chain, and pinned
# asOfSeq without a second fact. Emergency consumption is idempotent by
# consumptionId and monotonic; revocation stops further authority but never
# rewrites past consumption. History is never rewritten.
#
# Reuses round-1 event-time semantics, the round-2 authority chain and emergency
# budget, and the round-1 REVOKE-1 identifiers (CONSENT-1 / SUPPORTER-A / W-1).
class RevocationRaceTest < Minitest::Test
  include TestSupport

  R = Consent::ReasonCodes

  # REVOKE-1 revokes CONSENT-1 at this instant (round-1 material).
  REVOKE_AT = "2026-09-15T10:00:00.000000Z"

  def setup
    @ledger = seeded_ledger
  end

  def decide(supporter, scope, at, **kw)
    @ledger.evaluate(supporter_id: supporter, scope: scope, at: at, **kw)
  end

  # --- Microsecond boundary: the three mandated outcomes ------------------

  def test_one_microsecond_before_revocation_authorized
    d = decide("SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-09-15T09:59:59.999999Z")
    assert d.authorized
    assert_equal R::AUTHORIZED_DIRECT_CONSENT, d.reason_code
  end

  def test_exactly_at_revocation_instant_revoked
    d = decide("SUPPORTER-A", "LEGAL_AID_APPLICATION", REVOKE_AT)
    refute d.authorized
    assert_equal R::CONSENT_REVOKED, d.reason_code
  end

  def test_one_microsecond_after_revocation_revoked
    d = decide("SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-09-15T10:00:00.000001Z")
    refute d.authorized
    assert_equal R::CONSENT_REVOKED, d.reason_code
  end

  def test_boundary_survives_store_roundtrip
    # The three outcomes must hold when re-derived from the persisted log, i.e.
    # microsecond precision is not lost in serialization.
    ledger2 = fresh_ledger
    Consent::Seed.load_file(ledger2, File.expand_path("../materials/consent-cases.json", __dir__))
    before = ledger2.evaluate(supporter_id: "SUPPORTER-A", scope: "LEGAL_AID_APPLICATION", at: "2026-09-15T09:59:59.999999Z")
    at = ledger2.evaluate(supporter_id: "SUPPORTER-A", scope: "LEGAL_AID_APPLICATION", at: REVOKE_AT)
    after = ledger2.evaluate(supporter_id: "SUPPORTER-A", scope: "LEGAL_AID_APPLICATION", at: "2026-09-15T10:00:00.000001Z")
    assert_equal R::AUTHORIZED_DIRECT_CONSENT, before.reason_code
    assert_equal R::CONSENT_REVOKED, at.reason_code
    assert_equal R::CONSENT_REVOKED, after.reason_code
  end

  # --- Out-of-order revocation events -------------------------------------

  def test_out_of_order_revocations_earliest_wins
    # Two revocations recorded LATE-then-EARLY (out of event-time order). The
    # earliest instant governs; a later-arriving-but-earlier-dated revocation
    # cannot be undone, and a later-dated one cannot loosen it.
    l = fresh_ledger
    l.add_supporter("S"); l.define_scope("SC")
    l.grant_consent(id: "C", supporter_id: "S", scopes: ["SC"],
                    from: "2026-01-01T00:00:00Z", to: "2027-01-01T00:00:00Z", witness_id: "W")
    # Recorded order: a LATER revocation instant first...
    l.revoke_consent(consent_id: "C", at: "2026-08-01T00:00:00Z")
    # ...then an EARLIER one arrives.
    l.revoke_consent(consent_id: "C", at: "2026-06-01T00:00:00Z")

    # Between the two instants the earliest (06-01) already governs.
    d = l.evaluate(supporter_id: "S", scope: "SC", at: "2026-07-01T00:00:00Z")
    refute d.authorized
    assert_equal R::CONSENT_REVOKED, d.reason_code
    # Before the earliest instant: still authorized.
    d2 = l.evaluate(supporter_id: "S", scope: "SC", at: "2026-05-15T00:00:00Z")
    assert d2.authorized
  end

  # --- History is not rewritten by a later revocation ---------------------

  def test_pinned_decision_before_revocation_seq_unaffected
    at = "2026-09-20T00:00:00Z"
    revoke_seq = @ledger.events.find { |e| e.type == "CONSENT_REVOKED" }.seq
    before = decide("SUPPORTER-A", "HOUSING_APPLICATION", at, as_of_seq: revoke_seq - 1)
    current = decide("SUPPORTER-A", "HOUSING_APPLICATION", at)
    assert before.authorized, "pinned below the revocation seq, the fact is invisible"
    assert_equal R::AUTHORIZED_DIRECT_CONSENT, before.reason_code
    refute current.authorized
    assert_equal R::CONSENT_REVOKED, current.reason_code
  end

  # --- Idempotent resubmission of the same decision -----------------------

  def test_duplicate_decision_submission_is_idempotent
    req = "req-abc-123"
    first = @ledger.decide(supporter_id: "SUPPORTER-A", scope: "LEGAL_AID_APPLICATION",
                           at: "2026-09-01T00:00:00Z", request_id: req)
    seq_after_first = @ledger.max_seq

    # Resubmit the SAME request id many times, even interleaved with new facts.
    @ledger.add_supporter("NOISE-1")
    5.times do
      dup = @ledger.decide(supporter_id: "SUPPORTER-A", scope: "LEGAL_AID_APPLICATION",
                           at: "2026-09-01T00:00:00Z", request_id: req)
      assert_equal first.reason_code, dup.reason_code
      assert_equal first.authority_chain, dup.authority_chain
      assert_equal first.as_of_seq, dup.as_of_seq, "the pinned audit boundary must not move on resubmission"
    end

    # Exactly one DECISION_REQUESTED fact exists for this request.
    decisions = @ledger.events.select { |e| e.type == "DECISION_REQUESTED" }
    assert_equal 1, decisions.length
    assert_equal seq_after_first, @ledger.max_seq - 1 # only NOISE-1 added since
  end

  def test_duplicate_submission_cannot_widen_scope_across_revocation
    # A decision is pinned BEFORE the (later) revocation via its request id.
    # Resubmitting after the world has changed must still reproduce the original
    # authorized outcome — the duplicate cannot re-pin to a newer boundary, but
    # it also cannot widen scope: it only echoes the recorded fact.
    l = fresh_ledger
    l.add_supporter("S"); l.define_scope("SC")
    l.grant_consent(id: "C", supporter_id: "S", scopes: ["SC"],
                    from: "2026-01-01T00:00:00Z", to: "2027-01-01T00:00:00Z", witness_id: "W")
    first = l.decide(supporter_id: "S", scope: "SC", at: "2026-08-01T00:00:00Z", request_id: "d1")
    assert first.authorized

    # Now revoke, then resubmit the same decision id.
    l.revoke_consent(consent_id: "C", at: "2026-06-01T00:00:00Z")
    dup = l.decide(supporter_id: "S", scope: "SC", at: "2026-08-01T00:00:00Z", request_id: "d1")
    assert_equal first.reason_code, dup.reason_code
    assert_equal first.as_of_seq, dup.as_of_seq

    # A genuinely fresh decision (no reuse) now sees the revocation.
    fresh = l.decide(supporter_id: "S", scope: "SC", at: "2026-08-01T00:00:00Z", request_id: "d2")
    refute fresh.authorized
    assert_equal R::CONSENT_REVOKED, fresh.reason_code
  end

  # --- Emergency: consume budget, then revoke -----------------------------

  def emergency_ledger
    l = fresh_ledger
    l.add_supporter("S"); l.define_scope("LEGAL_AID_APPLICATION")
    l.set_emergency_policy(allowed_scope: "LEGAL_AID_APPLICATION", max_minutes: 30,
                           requires_review_event: false)
    l.invoke_emergency(id: "E1", supporter_id: "S", scope: "LEGAL_AID_APPLICATION",
                       at: "2026-06-01T12:00:00Z", max_minutes: 30)
    l
  end

  def test_partial_consumption_then_revoke_preserves_history
    l = emergency_ledger
    # Consume 10 of 30 at 12:05.
    l.consume_emergency(emergency_id: "E1", consumption_id: "c1", minutes: 10, at: "2026-06-01T12:05:00Z")
    # Still authorized at 12:06 (20 minutes remain, within the window).
    ok = l.evaluate(supporter_id: "S", scope: "LEGAL_AID_APPLICATION", at: "2026-06-01T12:06:00Z")
    assert ok.authorized
    assert_equal R::AUTHORIZED_EMERGENCY, ok.reason_code

    # Revoke at 12:07. From then on, further authority stops.
    l.revoke_emergency(emergency_id: "E1", at: "2026-06-01T12:07:00Z")
    after = l.evaluate(supporter_id: "S", scope: "LEGAL_AID_APPLICATION", at: "2026-06-01T12:08:00Z")
    refute after.authorized
    assert_equal R::EMERGENCY_REVOKED, after.reason_code

    # History intact: replaying the pre-revocation instant still authorizes, and
    # the consumed minutes recorded before the revocation are unchanged.
    replay = l.evaluate(supporter_id: "S", scope: "LEGAL_AID_APPLICATION", at: "2026-06-01T12:06:00Z")
    assert replay.authorized
    assert_equal R::AUTHORIZED_EMERGENCY, replay.reason_code
  end

  def test_revocation_reported_before_budget_or_timeout
    l = emergency_ledger
    l.consume_emergency(emergency_id: "E1", consumption_id: "c1", minutes: 30, at: "2026-06-01T12:05:00Z")
    # Budget is exhausted AND revoked after; revocation is the more specific,
    # higher-precedence cause once its instant is reached.
    l.revoke_emergency(emergency_id: "E1", at: "2026-06-01T12:06:00Z")
    d = l.evaluate(supporter_id: "S", scope: "LEGAL_AID_APPLICATION", at: "2026-06-01T12:07:00Z")
    assert_equal R::EMERGENCY_REVOKED, d.reason_code
  end

  def test_budget_exhausted_when_consumption_reaches_limit
    l = emergency_ledger
    l.consume_emergency(emergency_id: "E1", consumption_id: "c1", minutes: 30, at: "2026-06-01T12:05:00Z")
    d = l.evaluate(supporter_id: "S", scope: "LEGAL_AID_APPLICATION", at: "2026-06-01T12:06:00Z")
    refute d.authorized
    assert_equal R::EMERGENCY_BUDGET_EXHAUSTED, d.reason_code
  end

  def test_duplicate_consumption_does_not_double_drain_or_reset
    l = emergency_ledger
    # Consume 20 once.
    l.consume_emergency(emergency_id: "E1", consumption_id: "c1", minutes: 20, at: "2026-06-01T12:05:00Z")
    seq_after = l.max_seq
    # Resubmit the SAME consumption id repeatedly.
    5.times do
      l.consume_emergency(emergency_id: "E1", consumption_id: "c1", minutes: 20, at: "2026-06-01T12:05:00Z")
    end
    # No extra fact was appended (idempotent).
    assert_equal seq_after, l.max_seq
    # 20 consumed, 10 remain → still authorized (not double-drained to 40).
    d = l.evaluate(supporter_id: "S", scope: "LEGAL_AID_APPLICATION", at: "2026-06-01T12:06:00Z")
    assert d.authorized, "duplicate consumption must neither double-drain nor reset the budget"
    assert_equal R::AUTHORIZED_EMERGENCY, d.reason_code

    # A DIFFERENT consumption id does draw further budget: 20 + 15 = 35 >= 30.
    l.consume_emergency(emergency_id: "E1", consumption_id: "c2", minutes: 15, at: "2026-06-01T12:06:00Z")
    spent = l.evaluate(supporter_id: "S", scope: "LEGAL_AID_APPLICATION", at: "2026-06-01T12:07:00Z")
    refute spent.authorized
    assert_equal R::EMERGENCY_BUDGET_EXHAUSTED, spent.reason_code
  end

  def test_consumption_before_its_time_not_yet_counted
    # Consumption recorded with a future event-time is not counted before then:
    # accounting is as-of the decision instant.
    l = emergency_ledger
    l.consume_emergency(emergency_id: "E1", consumption_id: "c1", minutes: 30, at: "2026-06-01T12:20:00Z")
    # At 12:05, the 12:20 consumption hasn't happened yet → still authorized.
    early = l.evaluate(supporter_id: "S", scope: "LEGAL_AID_APPLICATION", at: "2026-06-01T12:05:00Z")
    assert early.authorized
    # At 12:21 it counts → exhausted.
    late = l.evaluate(supporter_id: "S", scope: "LEGAL_AID_APPLICATION", at: "2026-06-01T12:21:00Z")
    refute late.authorized
    assert_equal R::EMERGENCY_BUDGET_EXHAUSTED, late.reason_code
  end

  # --- Concurrency: submit + revoke racing, replays stable ----------------

  def test_concurrent_decisions_and_revocation_are_replay_stable
    l = fresh_ledger
    l.add_supporter("S"); l.define_scope("SC")
    l.grant_consent(id: "C", supporter_id: "S", scopes: ["SC"],
                    from: "2026-01-01T00:00:00Z", to: "2027-01-01T00:00:00Z", witness_id: "W")

    at = "2026-08-01T00:00:00Z"
    recorded = []
    mutex = Mutex.new
    threads = []
    threads << Thread.new { l.revoke_consent(consent_id: "C", at: "2026-06-01T00:00:00Z") }
    12.times do |i|
      threads << Thread.new do
        d = l.decide(supporter_id: "S", scope: "SC", at: at, request_id: "r#{i}")
        mutex.synchronize { recorded << [d.as_of_seq, d.reason_code, d.authorized, "r#{i}"] }
      end
    end
    threads.each(&:join)

    recorded.each do |seq, code, authorized, req|
      # Replay at the pinned seq reproduces the recorded reason code exactly.
      replay = l.evaluate(supporter_id: "S", scope: "SC", at: at, as_of_seq: seq)
      assert_equal code, replay.reason_code, "seq #{seq} must replay identically"
      assert_equal authorized, replay.authorized
      # Resubmitting the same request id echoes the same outcome + boundary.
      dup = l.decide(supporter_id: "S", scope: "SC", at: at, request_id: req)
      assert_equal code, dup.reason_code
      assert_equal seq, dup.as_of_seq
    end
  end
end
