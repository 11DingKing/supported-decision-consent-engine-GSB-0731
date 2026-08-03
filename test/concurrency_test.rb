# frozen_string_literal: true

require_relative "test_helper"
require "fileutils"

require_relative "../lib/store"

# Race-condition tests. Grants, revocations and evaluations are submitted
# concurrently against one SQLite database from many connections. Invariants:
#   1. the audit log is a contiguous, gap-free sequence (no lost writes)
#   2. a consent is revoked at most once (atomic validate+append)
#   3. every journaled decision replays to the identical verdict afterwards
#   4. no race ever widens scope: a scope that was never granted is never
#      authorized, and no decision chain references facts beyond its seq
class ConcurrencyTest < Minitest::Test
  DB = File.expand_path("../tmp/concurrency_#{Process.pid}.sqlite3", __dir__)

  def setup
    FileUtils.rm_f([DB, "#{DB}-wal", "#{DB}-shm"])
    @store = Store.new(DB)
    @store.in_transaction do
      @store.append_event(type: "PERSON_REGISTERED", payload: { "personId" => "PX" }, event_time: Time.now.utc)
      %w[SA SB].each do |s|
        @store.append_event(type: "SUPPORTER_REGISTERED", payload: { "personId" => "PX", "supporterId" => s }, event_time: Time.now.utc)
      end
      @store.append_event(type: "CONSENT_GRANTED",
                          payload: { "id" => "C-BASE", "personId" => "PX", "supporterId" => "SA",
                                     "scopes" => %w[LEGAL_AID_APPLICATION HOUSING_APPLICATION],
                                     "from" => "2026-08-01T00:00:00Z", "to" => "2026-12-01T00:00:00Z",
                                     "witnessId" => "W-1" },
                          event_time: Time.iso8601("2026-08-01T00:00:00Z"))
    end
    @base_seq = @store.max_seq
  end

  def teardown = @store.close

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

  def test_concurrent_grants_revokes_and_evaluations
    grant_threads = 8.times.map do |i|
      Thread.new do
        with_store_retry do |s|
          s.in_transaction do
            s.append_event(type: "CONSENT_GRANTED",
                           payload: { "id" => "C-G#{i}", "personId" => "PX", "supporterId" => "SB",
                                      "scopes" => ["LEGAL_AID_APPLICATION"],
                                      "from" => "2026-08-01T00:00:00Z", "to" => "2026-12-01T00:00:00Z",
                                      "witnessId" => "W-#{i}" },
                           event_time: Time.iso8601("2026-08-01T00:00:00Z"))
          end
        end
      end
    end

    revoke_threads = 8.times.map do |i|
      Thread.new do
        with_store_retry do |s|
          s.in_transaction do |seq|
            err = Domain::Validate.revocation(world: s.world(as_of_seq: seq), consent_id: "C-BASE")
            unless err
              s.append_event(type: "CONSENT_REVOKED",
                             payload: { "id" => "R-#{i}", "consentId" => "C-BASE", "at" => "2026-09-15T10:00:00Z" },
                             event_time: Time.iso8601("2026-09-15T10:00:00Z"))
            end
          end
        end
      end
    end

    eval_threads = 16.times.map do |i|
      Thread.new do
        with_store_retry do |s|
          scope = i.even? ? "LEGAL_AID_APPLICATION" : "MEDICAL_INFORMATION_VIEW"
          at = i % 4 < 2 ? Time.iso8601("2026-08-10T00:00:00Z") : Time.iso8601("2026-09-15T10:00:00Z")
          s.evaluate_and_record(person_id: "PX", supporter_id: i.even? ? "SA" : "SB", scope: scope, at: at)
        end
      end
    end

    (grant_threads + revoke_threads + eval_threads).each(&:join)

    # Invariant 1: contiguous audit sequence, no lost or reordered writes.
    seqs = @store.all_events.map(&:seq)
    assert_equal seqs.size, seqs.uniq.size
    assert_equal seqs.max - seqs.min + 1, seqs.size

    # Invariant 2: exactly one revocation survived the race.
    revocations = @store.all_events.select { |e| e.type == "CONSENT_REVOKED" }
    assert_equal 1, revocations.size

    grants = @store.all_events.select { |e| e.type == "CONSENT_GRANTED" }.size
    assert_equal 9, grants # 1 base + 8 raced

    decisions = @store.all_decisions
    assert_equal 16, decisions.size

    decisions.each do |d|
      # Invariant 3: replaying any decision against its pinned (time, seq)
      # reproduces the exact verdict — history was never rewritten.
      replay = @store.replay_decision(d["decisionId"])
      assert replay["replayMatches"], "decision #{d['decisionId']} replay diverged"

      # Invariant 4a: MEDICAL_INFORMATION_VIEW was never granted to anyone,
      # so no race may have produced an authorization for it.
      refute d["authorized"] if d["scope"] == "MEDICAL_INFORMATION_VIEW"

      # Invariant 4b: chains only reference facts visible at the pinned seq.
      d["chain"].each do |link|
        assert link["createdSeq"].nil? || link["createdSeq"] <= d["asOfSeq"]
      end

      # Invariant 4c: an authorized verdict at/after the revocation instant
      # must not exist for the revoked consent's direct holder.
      if d["supporterId"] == "SA" && d["scope"] == "LEGAL_AID_APPLICATION" && d["at"] >= "2026-09-15T10:00:00Z"
        refute d["authorized"], "race widened authority past revocation instant: #{d}"
        assert_equal "DENY_CONSENT_REVOKED", d["reasonCode"]
      end
    end
  end

  def test_audit_events_are_immutable_at_database_level
    assert_raises(SQLite3::ConstraintException) do
      @store.instance_variable_get(:@db).execute("UPDATE events SET payload = '{}' WHERE seq = 1")
    end
    assert_raises(SQLite3::ConstraintException) do
      @store.instance_variable_get(:@db).execute("DELETE FROM events WHERE seq = 1")
    end
  end
end
