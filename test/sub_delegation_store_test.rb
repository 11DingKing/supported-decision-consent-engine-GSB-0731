# frozen_string_literal: true

require_relative "test_helper"
require "fileutils"
require "json"

require_relative "../lib/store"

# Store-level sub-delegation scenarios reusing the literal round-1 identifiers
# (PERSON-01, SUPPORTER-A/B/C, CONSENT-1, W-1, scopes from
# materials/consent-cases.json). Covers: source revoked before the sub-chain
# is saved, a late-arriving sub-chain whose validity is computed by event
# time vs. audit seq, and a concurrent revoke-vs-save race.
class SubDelegationStoreTest < Minitest::Test
  DB = File.expand_path("../tmp/sub_delegation_#{Process.pid}.sqlite3", __dir__)
  REVOKE_AT = "2026-09-15T10:00:00Z"

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
                          event_time: Time.iso8601("2026-08-01T00:00:00Z"))
      @store.append_event(type: "WITNESS_RECORDED",
                          payload: { "consentId" => "CONSENT-1", "witnessId" => "W-1", "personId" => "PERSON-01" },
                          event_time: Time.iso8601("2026-08-01T00:00:00Z"))
    end
  end

  def teardown = @store.close

  # Same validate+append logic the HTTP route runs: on validation failure a
  # DELEGATION_REJECTED evidence event is journaled instead of the delegation.
  def save_subchain(store, id:, from:, to:, scopes:, effective_from:, valid_to: nil, budget: nil)
    store.in_transaction do |seq|
      world = store.world(as_of_seq: seq)
      err = Domain::Validate.delegation(world: world, source_consent_id: "CONSENT-1",
                                        from_supporter_id: from, to_supporter_id: to, scopes: scopes,
                                        effective_from: effective_from, valid_to: valid_to,
                                        emergency_budget_minutes: budget)
      if err
        evidence = Domain::Evidence.delegation_rejection(world: world, source_consent_id: "CONSENT-1",
                                                         from_supporter_id: from, to_supporter_id: to,
                                                         attempted_id: id, at: effective_from, reason: err)
        rej_seq = store.append_event(type: "DELEGATION_REJECTED",
                                     payload: { "id" => "REJ-#{id}", "attemptedDelegationId" => id,
                                                "sourceConsentId" => "CONSENT-1", "fromSupporterId" => from,
                                                "toSupporterId" => to, "reasonCode" => err, "chain" => evidence },
                                     event_time: effective_from)
        { rejected: err, seq: rej_seq }
      else
        created_seq = store.append_event(type: "DELEGATION_CREATED",
                                         payload: { "id" => id, "sourceConsentId" => "CONSENT-1", "fromSupporterId" => from,
                                                    "toSupporterId" => to, "scopes" => scopes,
                                                    "effectiveFrom" => effective_from.utc.iso8601,
                                                    "to" => valid_to&.utc&.iso8601, "emergencyBudgetMinutes" => budget },
                                         event_time: effective_from)
        { created: id, seq: created_seq }
      end
    end
  end

  def revoke!(at: REVOKE_AT)
    @store.in_transaction do |seq|
      err = Domain::Validate.revocation(world: @store.world(as_of_seq: seq), consent_id: "CONSENT-1")
      @store.append_event(type: "CONSENT_REVOKED",
                          payload: { "id" => "REVOKE-1", "consentId" => "CONSENT-1", "at" => at },
                          event_time: Time.iso8601(at)) unless err
    end
  end

  def events(type) = @store.all_events.select { |e| e.type == type }

  # Scenario 1: the source is revoked before the sub-chain is saved — the
  # attempt fails and its rejection evidence is immutable and scope-redacted.
  def test_revoke_before_subchain_save_leaves_redacted_evidence
    revoke!
    result = save_subchain(@store, id: "DELEG-TOOLATE", from: "SUPPORTER-A", to: "SUPPORTER-B",
                           scopes: ["LEGAL_AID_APPLICATION"], effective_from: Time.iso8601("2026-09-16T00:00:00Z"))

    assert_equal "DELEGATION_SOURCE_REVOKED", result[:rejected]
    assert_equal 0, events("DELEGATION_CREATED").size

    rejected = events("DELEGATION_REJECTED")
    assert_equal 1, rejected.size
    payload = rejected.first.payload
    assert_equal "DELEGATION_SOURCE_REVOKED", payload["reasonCode"]
    assert_equal "DELEG-TOOLATE", payload["attemptedDelegationId"]
    assert rejected.first.seq > events("CONSENT_REVOKED").first.seq

    json = JSON.generate(payload["chain"])
    refute_includes json, "LEGAL_AID_APPLICATION"
    assert_equal "rejected", payload["chain"].last["status"]
    assert_equal "revoked", payload["chain"].first["status"]
  end

  # Scenario 2: the sub-chain arrives late (higher audit seq than the
  # revocation) but is effective earlier (lower event time). Validity splits
  # by event time, and decisions pinned before its arrival do not change.
  def test_late_arriving_subchain_by_event_time_and_audit_seq
    revoke!

    early = @store.evaluate_and_record(person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
                                       scope: "LEGAL_AID_APPLICATION", at: Time.iso8601("2026-09-14T12:00:00Z"))
    assert_equal "DENY_NO_CONSENT", early["reasonCode"]
    revoke_seq = events("CONSENT_REVOKED").first.seq
    assert_equal revoke_seq, early["asOfSeq"]

    late = save_subchain(@store, id: "DELEG-LATE", from: "SUPPORTER-A", to: "SUPPORTER-B",
                         scopes: ["LEGAL_AID_APPLICATION"],
                         effective_from: Time.iso8601("2026-09-14T00:00:00Z"), budget: 10)
    assert late[:created], "late sub-chain effective before revocation must be loggable: #{late}"
    assert late[:seq] > revoke_seq

    # Same event time, later audit seq: now the chain exists and authorizes.
    after = @store.evaluate_and_record(person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
                                       scope: "LEGAL_AID_APPLICATION", at: Time.iso8601("2026-09-14T12:00:00Z"))
    assert_equal "OK_DELEGATED", after["reasonCode"]
    assert_equal "DELEG-LATE", after["chain"][1]["id"]

    # The earlier decision is pinned to its seq: replaying it must not see
    # the late arrival — history is never rewritten.
    replay = @store.replay_decision(early["decisionId"])
    assert replay["replayMatches"]
    assert_equal "DENY_NO_CONSENT", replay["replay"]["reasonCode"]

    # Past the revocation instant the late sub-chain is dead again.
    post_revoke = @store.evaluate_and_record(person_id: "PERSON-01", supporter_id: "SUPPORTER-B",
                                             scope: "LEGAL_AID_APPLICATION", at: Time.iso8601("2026-09-15T11:00:00Z"))
    assert_equal "DENY_DELEGATION_SOURCE_REVOKED", post_revoke["reasonCode"]
  end

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

  # Scenario 3: concurrent revoke vs. sub-chain saves. Whatever the commit
  # order, no sub-holder is ever authorized at or after the revocation
  # instant, every failed attempt leaves evidence, and all verdicts replay.
  def test_concurrent_revoke_vs_subchain_saves
    revoke_thread = Thread.new do
      with_store_retry do |s|
        s.in_transaction do |seq|
          err = Domain::Validate.revocation(world: s.world(as_of_seq: seq), consent_id: "CONSENT-1")
          s.append_event(type: "CONSENT_REVOKED",
                         payload: { "id" => "REVOKE-1", "consentId" => "CONSENT-1", "at" => REVOKE_AT },
                         event_time: Time.iso8601(REVOKE_AT)) unless err
        end
      end
    end

    save_threads = 6.times.map do |i|
      Thread.new do
        with_store_retry do |s|
          save_subchain(s, id: "DELEG-RACE-#{i}", from: "SUPPORTER-A", to: "SUPPORTER-#{%w[B C][i % 2]}",
                        scopes: ["LEGAL_AID_APPLICATION"],
                        effective_from: Time.iso8601("2026-09-16T00:00:00Z"))
        end
      end
    end

    eval_threads = 6.times.map do |i|
      Thread.new do
        with_store_retry do |s|
          s.evaluate_and_record(person_id: "PERSON-01", supporter_id: "SUPPORTER-#{%w[B C][i % 2]}",
                                scope: "LEGAL_AID_APPLICATION", at: Time.iso8601("2026-09-16T02:00:00Z"))
        end
      end
    end

    save_results = save_threads.map(&:value)
    eval_threads.each(&:join)
    revoke_thread.join

    # Audit log stayed contiguous under the race.
    seqs = @store.all_events.map(&:seq)
    assert_equal seqs.size, seqs.uniq.size
    assert_equal seqs.max - seqs.min + 1, seqs.size

    # Every raced attempt either created a delegation or left rejection
    # evidence — never neither, never both.
    created = events("DELEGATION_CREATED")
    rejected = events("DELEGATION_REJECTED")
    assert_equal save_results.count { |r| r[:created] }, created.size
    assert_equal save_results.count { |r| r[:rejected] }, rejected.size
    assert rejected.all? { |e| e.payload["reasonCode"] == "DELEGATION_SOURCE_REVOKED" } if created.empty?

    # No sub-holder was authorized at/after the revocation instant, whether
    # their sub-chain won the race or not.
    @store.all_decisions.each do |d|
      next unless d["at"] >= REVOKE_AT

      refute d["authorized"], "race authorized a sub-holder past revocation: #{d}"
      replay = @store.replay_decision(d["decisionId"])
      assert replay["replayMatches"], "decision #{d['decisionId']} replay diverged"
    end

    # Rejection evidence never carries scope contents.
    rejected.each do |e|
      refute_includes JSON.generate(e.payload["chain"]), "LEGAL_AID_APPLICATION"
    end
  end
end
