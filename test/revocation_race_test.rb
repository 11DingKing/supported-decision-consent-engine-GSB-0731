# frozen_string_literal: true

require_relative "test_helper"
require "fileutils"
require "json"

require_relative "../lib/store"

# Round 3: REVOKE-1 vs. in-flight decisions. Microsecond boundary semantics,
# out-of-order revocation events, duplicate decision submissions, and an
# emergency episode that has burned part of its budget before the revocation.
# Literal round-1 identifiers: PERSON-01, SUPPORTER-A/B/C, CONSENT-1, W-1.
class RevocationRaceTest < Minitest::Test
  DB = File.expand_path("../tmp/revocation_race_#{Process.pid}.sqlite3", __dir__)
  REVOKE_AT = "2026-09-15T10:00:00Z"
  T = ->(s) { Time.iso8601(s) }

  def setup
    FileUtils.rm_f([DB, "#{DB}-wal", "#{DB}-shm"])
    @store = Store.new(DB)
    @store.in_transaction do
      @store.append_event(type: "PERSON_REGISTERED", payload: { "personId" => "PERSON-01" }, event_time: Time.now.utc)
      %w[SUPPORTER-A SUPPORTER-B SUPPORTER-C].each do |s|
        @store.append_event(type: "SUPPORTER_REGISTERED", payload: { "personId" => "PERSON-01", "supporterId" => s }, event_time: Time.now.utc)
      end
      @store.append_event(type: "EMERGENCY_POLICY_SET",
                          payload: { "personId" => "PERSON-01", "allowedScope" => "LEGAL_AID_APPLICATION",
                                     "maxMinutes" => 30, "requiresReviewEvent" => true },
                          event_time: Time.now.utc)
      @store.append_event(type: "CONSENT_GRANTED",
                          payload: { "id" => "CONSENT-1", "personId" => "PERSON-01", "supporterId" => "SUPPORTER-A",
                                     "scopes" => %w[LEGAL_AID_APPLICATION HOUSING_APPLICATION],
                                     "from" => "2026-08-01T00:00:00Z", "to" => "2026-12-01T00:00:00Z",
                                     "witnessId" => "W-1" },
                          event_time: T.call("2026-08-01T00:00:00Z"))
      @store.append_event(type: "WITNESS_RECORDED",
                          payload: { "consentId" => "CONSENT-1", "witnessId" => "W-1", "personId" => "PERSON-01" },
                          event_time: T.call("2026-08-01T00:00:00Z"))
      # DELEG-OK: budget-bearing chain for SUPPORTER-B (emergency cap 20).
      @store.append_event(type: "DELEGATION_CREATED",
                          payload: { "id" => "DELEG-OK", "sourceConsentId" => "CONSENT-1",
                                     "fromSupporterId" => "SUPPORTER-A", "toSupporterId" => "SUPPORTER-B",
                                     "scopes" => ["HOUSING_APPLICATION"],
                                     "effectiveFrom" => "2026-08-01T00:00:00Z", "to" => "2026-10-01T00:00:00Z",
                                     "emergencyBudgetMinutes" => 20 },
                          event_time: T.call("2026-08-01T00:00:00Z"))
    end
  end

  def teardown = @store.close

  def revoke!(at: REVOKE_AT, id: "REVOKE-1", store: @store)
    store.in_transaction do |seq|
      err = Domain::Validate.revocation(world: store.world(as_of_seq: seq), consent_id: "CONSENT-1")
      if err
        { rejected: err }
      else
        s = store.append_event(type: "CONSENT_REVOKED",
                               payload: { "id" => id, "consentId" => "CONSENT-1", "at" => at },
                               event_time: T.call(at))
        { created: id, seq: s }
      end
    end
  end

  def evaluate(supporter, scope, at, request_id: nil, store: @store)
    store.evaluate_and_record(person_id: "PERSON-01", supporter_id: supporter,
                              scope: scope, at: T.call(at), request_id: request_id)
  end

  def events(type) = @store.all_events.select { |e| e.type == type }

  def with_store_retry
    s = Store.new(DB)
    attempts = 0
    begin
      yield s
    rescue SQLite3::BusyException
      attempts += 1
      sleep 0.01 * attempts
      retry if attempts < 20
      raise
    ensure
      s.close
    end
  end

  # --- the three outcomes around the revocation instant -----------------------

  def test_three_outcomes_pure_domain
    world = @store.world
    revoke!(at: REVOKE_AT)
    world = @store.world

    exact = Domain::Authorizer.evaluate(world: world, supporter_id: "SUPPORTER-A",
                                        scope: "LEGAL_AID_APPLICATION", at: T.call(REVOKE_AT))
    assert_equal "DENY_CONSENT_REVOKED", exact.reason_code

    before = Domain::Authorizer.evaluate(world: world, supporter_id: "SUPPORTER-A",
                                         scope: "LEGAL_AID_APPLICATION", at: T.call("2026-09-15T09:59:59.999999Z"))
    assert_equal "OK_DIRECT", before.reason_code

    after = Domain::Authorizer.evaluate(world: world, supporter_id: "SUPPORTER-A",
                                        scope: "LEGAL_AID_APPLICATION", at: T.call("2026-09-15T10:00:00.000001Z"))
    assert_equal "DENY_CONSENT_REVOKED", after.reason_code
  end

  def test_three_outcomes_survive_persistence_and_replay
    revoke!(at: REVOKE_AT)

    exact = evaluate("SUPPORTER-A", "LEGAL_AID_APPLICATION", REVOKE_AT)
    before = evaluate("SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-09-15T09:59:59.999999Z")
    after = evaluate("SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-09-15T10:00:00.000001Z")

    assert_equal "DENY_CONSENT_REVOKED", exact["reasonCode"]
    assert_equal "OK_DIRECT", before["reasonCode"]
    assert_equal "DENY_CONSENT_REVOKED", after["reasonCode"]
    assert_equal REVOKE_AT, exact["chain"].first["revokedAt"]
    # Microsecond event times survive the DB round-trip verbatim.
    assert_equal "2026-09-15T09:59:59.999999Z", before["at"]
    assert_equal "2026-09-15T10:00:00.000001Z", after["at"]

    [exact, before, after].each do |d|
      replay = @store.replay_decision(d["decisionId"])
      assert replay["replayMatches"], "#{d['at']} replay diverged"
      assert_equal d["asOfSeq"], replay["asOfSeq"]
    end
  end

  def test_microsecond_revocation_instant_itself
    revoke!(at: "2026-09-15T10:00:00.500000Z")
    assert_equal "OK_DIRECT", evaluate("SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-09-15T10:00:00.499999Z")["reasonCode"]
    assert_equal "DENY_CONSENT_REVOKED", evaluate("SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-09-15T10:00:00.500000Z")["reasonCode"]
    assert_equal "DENY_CONSENT_REVOKED", evaluate("SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-09-15T10:00:00.500001Z")["reasonCode"]
  end

  # --- out-of-order revocation events ------------------------------------------

  # A revocation logged first wins; a later attempt to backdate an earlier
  # revocation instant is rejected and never rewrites history.
  def test_out_of_order_revocation_events_first_logged_wins
    assert revoke!(at: REVOKE_AT, id: "REVOKE-2")[:created]
    backdated = revoke!(at: "2026-09-15T09:00:00Z", id: "REVOKE-1")
    assert_equal "ALREADY_REVOKED", backdated[:rejected]
    assert_equal 1, events("CONSENT_REVOKED").size

    # The effective instant stays 10:00 even though a 09:00 revocation was
    # attempted afterwards.
    assert_equal "OK_DIRECT", evaluate("SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-09-15T09:30:00Z")["reasonCode"]
    assert_equal "DENY_CONSENT_REVOKED", evaluate("SUPPORTER-A", "LEGAL_AID_APPLICATION", REVOKE_AT)["reasonCode"]
    # Delegated chain follows the same instant.
    assert_equal "OK_DELEGATED", evaluate("SUPPORTER-B", "HOUSING_APPLICATION", "2026-09-15T09:30:00Z")["reasonCode"]
    assert_equal "DENY_DELEGATION_SOURCE_REVOKED", evaluate("SUPPORTER-B", "HOUSING_APPLICATION", REVOKE_AT)["reasonCode"]
  end

  # --- duplicate decision submission --------------------------------------------

  def test_duplicate_submission_returns_pinned_verdict
    first = evaluate("SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-08-10T00:00:00Z", request_id: "REQ-1")
    refute first["duplicate"]

    second = evaluate("SUPPORTER-A", "LEGAL_AID_APPLICATION", "2026-08-10T00:00:00Z", request_id: "REQ-1")
    assert second["duplicate"]
    assert_equal first["decisionId"], second["decisionId"]
    assert_equal first.slice("reasonCode", "authorized", "chain", "asOfSeq"),
                 second.slice("reasonCode", "authorized", "chain", "asOfSeq")
    assert_equal 1, @store.all_decisions.size
  end

  # Resubmission must not widen scope: even after a late-arriving sub-chain
  # makes the same event time authorizable, the duplicate keeps its pinned
  # denial. A genuinely new requestId re-queries deliberately.
  def test_duplicate_submission_cannot_expand_scope
    pinned = evaluate("SUPPORTER-C", "LEGAL_AID_APPLICATION", "2026-09-14T12:00:00Z", request_id: "REQ-C")
    assert_equal "DENY_NO_CONSENT", pinned["reasonCode"]

    @store.in_transaction do
      @store.append_event(type: "DELEGATION_CREATED",
                          payload: { "id" => "DELEG-LATE", "sourceConsentId" => "CONSENT-1",
                                     "fromSupporterId" => "SUPPORTER-A", "toSupporterId" => "SUPPORTER-C",
                                     "scopes" => ["LEGAL_AID_APPLICATION"],
                                     "effectiveFrom" => "2026-09-14T00:00:00Z", "to" => nil,
                                     "emergencyBudgetMinutes" => nil },
                          event_time: T.call("2026-09-14T00:00:00Z"))
    end

    duplicate = evaluate("SUPPORTER-C", "LEGAL_AID_APPLICATION", "2026-09-14T12:00:00Z", request_id: "REQ-C")
    assert duplicate["duplicate"]
    assert_equal "DENY_NO_CONSENT", duplicate["reasonCode"]
    refute duplicate["authorized"]

    fresh = evaluate("SUPPORTER-C", "LEGAL_AID_APPLICATION", "2026-09-14T12:00:00Z", request_id: "REQ-C-2")
    refute fresh["duplicate"]
    assert_equal "OK_DELEGATED", fresh["reasonCode"]

    assert @store.replay_decision(pinned["decisionId"])["replayMatches"]
    assert @store.replay_decision(fresh["decisionId"])["replayMatches"]
  end

  # --- emergency budget used, then revoked ---------------------------------------

  # Budget is pinned to the episode start: revocation mid-episode neither
  # resets it to the policy window nor expands it.
  def test_emergency_budget_pinned_at_episode_start_across_revocation
    @store.in_transaction do
      @store.append_event(type: "EMERGENCY_STARTED",
                          payload: { "id" => "EMG-1", "personId" => "PERSON-01", "supporterId" => "SUPPORTER-B",
                                     "scope" => "LEGAL_AID_APPLICATION", "startedAt" => "2026-09-15T09:30:00Z",
                                     "maxMinutes" => 30 },
                          event_time: T.call("2026-09-15T09:30:00Z"))
    end

    within = evaluate("SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-09-15T09:40:00Z")
    assert_equal "OK_EMERGENCY_REVIEW_PENDING", within["reasonCode"]
    assert_equal 20, within["chain"].first["budgetCapMinutes"]
    assert_equal "2026-09-15T09:30:00Z", within["chain"].first["budgetPinnedAt"]

    # Revoke the source mid-episode (10:00), budget already partly used.
    revoke!(at: REVOKE_AT)

    # Cap stays pinned at 20 (computed at episode start): still fine at +18m…
    still_ok = evaluate("SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-09-15T09:48:00Z")
    assert_equal "OK_EMERGENCY_REVIEW_PENDING", still_ok["reasonCode"]
    assert_equal 20, still_ok["chain"].first["budgetCapMinutes"]

    # …and still exceeded at +25m. No reset to the 30-minute policy window.
    exceeded = evaluate("SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-09-15T09:55:00Z")
    assert_equal "DENY_EMERGENCY_BUDGET_EXCEEDED", exceeded["reasonCode"]

    # Re-submitting the same evaluation cannot reset the budget either.
    dup = evaluate("SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-09-15T09:55:00Z", request_id: "REQ-EMG")
    assert_equal "DENY_EMERGENCY_BUDGET_EXCEEDED", dup["reasonCode"]
    again = evaluate("SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-09-15T09:55:00Z", request_id: "REQ-EMG")
    assert again["duplicate"]
    assert_equal "DENY_EMERGENCY_BUDGET_EXCEEDED", again["reasonCode"]
    refute again["authorized"]
  end

  # --- concurrent REVOKE-1 vs. in-flight decisions at the µs boundaries ---------

  def test_concurrent_revoke_vs_inflight_decisions
    times = ["2026-09-15T09:59:59.999999Z", REVOKE_AT, "2026-09-15T10:00:00.000001Z"]

    revoke_thread = Thread.new { with_store_retry { |s| revoke!(store: s) } }

    eval_threads = (0..11).map do |i|
      Thread.new do
        with_store_retry do |s|
          supporter = i.even? ? "SUPPORTER-A" : "SUPPORTER-B"
          scope = i.even? ? "LEGAL_AID_APPLICATION" : "HOUSING_APPLICATION"
          s.evaluate_and_record(person_id: "PERSON-01", supporter_id: supporter,
                                scope: scope, at: T.call(times[i % 3]), request_id: "REQ-RACE-#{i}")
        end
      end
    end
    results = eval_threads.map(&:value)
    revoke_thread.join

    revoke_seq = events("CONSENT_REVOKED").first.seq
    assert_equal 1, events("CONSENT_REVOKED").size

    results.each do |d|
      replay = @store.replay_decision(d["decisionId"])
      assert replay["replayMatches"], "replay diverged for #{d['decisionId']}"
      assert_equal d["asOfSeq"], replay["asOfSeq"]

      if T.call(d["at"]) < T.call(REVOKE_AT)
        # One microsecond early: revocation (10:00) can never apply.
        assert d["authorized"], "#{d['at']} must authorize: #{d['reasonCode']}"
      elsif d["authorized"]
        # At/after the instant an authorization is only possible from a
        # snapshot taken before the revocation was logged — and replaying
        # that exact snapshot must agree.
        assert d["asOfSeq"] < revoke_seq, "authorized past revocation visibility: #{d}"
      else
        assert_includes %w[DENY_CONSENT_REVOKED DENY_DELEGATION_SOURCE_REVOKED], d["reasonCode"]
        assert d["asOfSeq"] >= revoke_seq, "denied without seeing revocation: #{d}"
      end
    end

    # Duplicated race submissions return their pinned verdicts verbatim.
    rerun = evaluate("SUPPORTER-A", "LEGAL_AID_APPLICATION", REVOKE_AT, request_id: "REQ-RACE-0")
    assert rerun["duplicate"]
    assert_equal results.first["reasonCode"], rerun["reasonCode"]
  end
end
