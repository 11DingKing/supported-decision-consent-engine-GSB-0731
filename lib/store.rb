# frozen_string_literal: true

require "json"
require "securerandom"
require "sqlite3"
require "time"

require_relative "domain"

# SQLite persistence: an append-only audit event log plus an immutable
# decision journal. This class performs NO authorization judgment; it only
# stores facts, hands Domain::World snapshots to the domain layer, and
# persists the verdicts the domain layer returns.
class Store
  Event = Struct.new(:seq, :type, :payload, :event_time, keyword_init: true)

  def initialize(path)
    @path = path
    @db = SQLite3::Database.new(path)
    @db.results_as_hash = true
    @db.busy_timeout = 10_000
    @db.execute("PRAGMA journal_mode=WAL")
    @db.execute("PRAGMA foreign_keys=ON")
    migrate!
  end

  def close = @db.close

  def migrate!
    @db.execute_batch(<<~SQL)
      CREATE TABLE IF NOT EXISTS events (
        seq        INTEGER PRIMARY KEY AUTOINCREMENT,
        type       TEXT NOT NULL,
        payload    TEXT NOT NULL,
        event_time TEXT NOT NULL,
        recorded_at TEXT NOT NULL
      );
      CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
      BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;
      CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
      BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;

      CREATE TABLE IF NOT EXISTS decisions (
        id         TEXT PRIMARY KEY,
        person_id  TEXT NOT NULL,
        supporter_id TEXT NOT NULL,
        scope      TEXT NOT NULL,
        event_time TEXT NOT NULL,
        as_of_seq  INTEGER NOT NULL,
        reason_code TEXT NOT NULL,
        authorized INTEGER NOT NULL,
        chain      TEXT NOT NULL,
        recorded_at TEXT NOT NULL
      );
      CREATE TRIGGER IF NOT EXISTS decisions_no_update BEFORE UPDATE ON decisions
      BEGIN SELECT RAISE(ABORT, 'decisions are immutable'); END;
      CREATE TRIGGER IF NOT EXISTS decisions_no_delete BEFORE DELETE ON decisions
      BEGIN SELECT RAISE(ABORT, 'decisions are immutable'); END;
    SQL
  end

  # Run a block inside an IMMEDIATE transaction. The block receives the
  # current max seq, so write-time validation and the append are atomic with
  # respect to competing writers (grant vs. revocation races serialize here).
  def in_transaction
    @db.execute("BEGIN IMMEDIATE")
    committed = false
    begin
      result = yield(max_seq)
      @db.execute("COMMIT")
      committed = true
      result
    ensure
      # Runs for exceptions AND non-local exits (e.g. Sinatra's throw :halt),
      # so a request that aborts mid-transaction never leaks an open one.
      (@db.execute("ROLLBACK") rescue nil) unless committed
    end
  end

  def max_seq
    @db.get_first_value("SELECT COALESCE(MAX(seq), 0) FROM events").to_i
  end

  def append_event(type:, payload:, event_time:)
    @db.execute(
      "INSERT INTO events (type, payload, event_time, recorded_at) VALUES (?, ?, ?, ?)",
      [type, JSON.generate(payload), event_time.utc.iso8601, Time.now.utc.iso8601]
    )
    @db.last_insert_row_id
  end

  def events_up_to(seq)
    @db.execute(
      "SELECT seq, type, payload, event_time FROM events WHERE seq <= ? ORDER BY seq ASC", [seq]
    ).map do |row|
      Event.new(seq: row["seq"].to_i, type: row["type"],
                payload: JSON.parse(row["payload"]), event_time: Time.iso8601(row["event_time"]))
    end
  end

  # Rebuild the pure domain snapshot visible at audit sequence `seq`.
  def world(as_of_seq: max_seq)
    WorldBuilder.build(events_up_to(as_of_seq), as_of_seq)
  end

  # Evaluate-and-record atomically: snapshot seq, evaluate, journal the
  # decision against exactly that seq, all inside one IMMEDIATE transaction.
  def evaluate_and_record(person_id:, supporter_id:, scope:, at:)
    in_transaction do |seq|
      snapshot = world(as_of_seq: seq)
      decision = Domain::Authorizer.evaluate(world: snapshot, supporter_id: supporter_id, scope: scope, at: at)
      id = "DEC-#{SecureRandom.uuid}"
      @db.execute(
        "INSERT INTO decisions (id, person_id, supporter_id, scope, event_time, as_of_seq, reason_code, authorized, chain, recorded_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [id, person_id, supporter_id, scope, at.utc.iso8601, seq,
         decision.reason_code, decision.authorized ? 1 : 0,
         JSON.generate(decision.chain), Time.now.utc.iso8601]
      )
      { "decisionId" => id, "personId" => person_id, "supporterId" => supporter_id,
        "scope" => scope, "at" => at.utc.iso8601, "asOfSeq" => seq,
        "reasonCode" => decision.reason_code, "authorized" => decision.authorized,
        "chain" => decision.chain }
    end
  end

  def fetch_decision(id)
    row = @db.get_first_row("SELECT * FROM decisions WHERE id = ?", [id])
    return nil if row.nil?

    { "decisionId" => row["id"], "personId" => row["person_id"],
      "supporterId" => row["supporter_id"], "scope" => row["scope"],
      "at" => row["event_time"], "asOfSeq" => row["as_of_seq"].to_i,
      "reasonCode" => row["reason_code"], "authorized" => row["authorized"] == 1,
      "chain" => JSON.parse(row["chain"]) }
  end

  # Replay a stored decision: rebuild the world exactly as of the recorded
  # seq and re-evaluate at the recorded event time. Returns the replayed
  # verdict plus whether it matches the journaled one.
  def replay_decision(id)
    stored = fetch_decision(id)
    return nil if stored.nil?

    snapshot = world(as_of_seq: stored["asOfSeq"])
    decision = Domain::Authorizer.evaluate(world: snapshot, supporter_id: stored["supporterId"],
                                           scope: stored["scope"], at: Time.iso8601(stored["at"]))
    replayed = { "reasonCode" => decision.reason_code, "authorized" => decision.authorized,
                 "chain" => decision.chain }
    stored.merge("replay" => replayed,
                 "replayMatches" => replayed == stored.slice("reasonCode", "authorized", "chain"))
  end

  def all_decisions
    @db.execute("SELECT id FROM decisions ORDER BY recorded_at ASC").map { |r| fetch_decision(r["id"]) }
  end

  def all_events = events_up_to(max_seq)

  def audit_trail(person_id)
    events_up_to(max_seq).select do |e|
      cid = e.payload["consentId"] || e.payload["sourceConsentId"]
      e.payload["personId"] == person_id || (cid && consent_person(cid) == person_id)
    end.map do |e|
      { "seq" => e.seq, "type" => e.type, "eventTime" => e.event_time.utc.iso8601, "payload" => e.payload }
    end
  end

  private

  def consent_person(consent_id)
    row = @db.get_first_row(
      "SELECT payload FROM events WHERE type = 'CONSENT_GRANTED' AND json_extract(payload, '$.id') = ?", [consent_id]
    )
    row && JSON.parse(row["payload"])["personId"]
  end
end

# Translates the flat event log into pure domain objects. Still no
# authorization decisions here — only fact assembly.
module WorldBuilder
  module_function

  def build(events, as_of_seq)
    persons = []
    supporters = []
    consents = []
    delegations = []
    revocations = []
    emergencies = {}
    policies = {}

    events.each do |e|
      p = e.payload
      case e.type
      when "PERSON_REGISTERED"
        persons << p["personId"] unless persons.include?(p["personId"])
      when "SUPPORTER_REGISTERED"
        supporters << p["supporterId"] unless supporters.include?(p["supporterId"])
      when "EMERGENCY_POLICY_SET"
        policies[p["personId"]] = Domain::EmergencyPolicy.new(
          allowed_scope: p["allowedScope"], max_minutes: p["maxMinutes"],
          requires_review_event: p["requiresReviewEvent"]
        )
      when "CONSENT_GRANTED"
        consents << Domain::Consent.new(
          id: p["id"], person_id: p["personId"], supporter_id: p["supporterId"],
          scopes: p["scopes"], valid_from: Time.iso8601(p["from"]), valid_to: Time.iso8601(p["to"]),
          witness_id: p["witnessId"], emergency_budget_minutes: p["emergencyBudgetMinutes"]
        )
      when "CONSENT_REVOKED"
        # First revocation wins; later duplicates are kept in the log but
        # never move the effective revocation instant.
        unless revocations.any? { |r| r.consent_id == p["consentId"] }
          revocations << Domain::Revocation.new(id: p["id"], consent_id: p["consentId"], at: Time.iso8601(p["at"]))
        end
      when "DELEGATION_CREATED"
        delegations << Domain::Delegation.new(
          id: p["id"], source_consent_id: p["sourceConsentId"],
          from_supporter_id: p["fromSupporterId"], to_supporter_id: p["toSupporterId"],
          scopes: p["scopes"], effective_from: Time.iso8601(p["effectiveFrom"]),
          valid_to: p["to"] && Time.iso8601(p["to"]), created_seq: e.seq,
          emergency_budget_minutes: p["emergencyBudgetMinutes"]
        )
      when "EMERGENCY_STARTED"
        emergencies[p["id"]] = Domain::EmergencyEpisode.new(
          id: p["id"], supporter_id: p["supporterId"], scope: p["scope"],
          started_at: Time.iso8601(p["startedAt"]), max_minutes: p["maxMinutes"], reviewed_at: nil
        )
      when "EMERGENCY_REVIEWED"
        ep = emergencies[p["emergencyId"]]
        ep.reviewed_at = Time.iso8601(p["at"]) if ep && ep.reviewed_at.nil?
      end
    end

    Domain::World.new(persons: persons, supporters: supporters, consents: consents,
                      delegations: delegations, revocations: revocations,
                      emergencies: emergencies.values, emergency_policies: policies,
                      as_of_seq: as_of_seq)
  end
end
