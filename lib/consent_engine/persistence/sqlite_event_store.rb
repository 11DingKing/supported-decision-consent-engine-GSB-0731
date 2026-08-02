require "sqlite3"
require "json"
require "securerandom"
require_relative "../clock"
require_relative "../domain/audit_event"
require_relative "../domain/consent_boundary"
require_relative "../domain/decision_result"
require_relative "../domain/emergency_policy"

module ConsentEngine
  module Persistence
    class SqliteEventStore
      class ConcurrencyError < StandardError; end

      def initialize(db_path)
        @db_path = db_path
        @mutex = Mutex.new
        setup_schema
      end

      def append(event_type:, person_id:, payload:, occurred_at:, event_id: nil)
        event_id ||= "EVT-#{SecureRandom.uuid}"
        occurred_at = Clock.parse_time(occurred_at)
        recorded_at = Clock.now

        @mutex.synchronize do
          with_db do |db|
            db.execute(
              "INSERT INTO events (event_id, event_type, person_id, payload, occurred_at, recorded_at)
               VALUES (?, ?, ?, ?, ?, ?)",
              [
                event_id,
                event_type,
                person_id,
                JSON.generate(payload),
                Clock.iso8601(occurred_at),
                Clock.iso8601(recorded_at)
              ]
            )
            seq = db.last_insert_row_id
            read_event(db, seq)
          end
        end
      end

      def evaluate_decision(person_id:, supporter_id:, scope:, at:, policy:)
        at = Clock.parse_time(at)
        @mutex.synchronize do
          with_db do |db|
            db.transaction(:immediate)
              events = read_events(db)
              seen = events.map(&:sequence).max || 0

              request = {
                person_id: person_id,
                supporter_id: supporter_id,
                scope: scope,
                at: at
              }

              result = Domain::ConsentBoundary.evaluate(events, request, policy)

              decision_id = "DEC-#{SecureRandom.uuid}"
              policy_snapshot = policy ? {
                "allowedScope" => policy.allowed_scope,
                "maxMinutes" => policy.max_minutes,
                "requiresReviewEvent" => policy.requires_review_event
              } : nil
              payload = {
                "decisionId" => decision_id,
                "personId" => person_id,
                "supporterId" => supporter_id,
                "scope" => scope,
                "decisionAt" => Clock.iso8601(at),
                "seenSequence" => seen,
                "reasonCode" => result.reason_code,
                "authorized" => result.authorized?,
                "chain" => result.chain.map(&:as_json),
                "emergency" => result.emergency,
                "policySnapshot" => policy_snapshot
              }.compact

              db.execute(
                "INSERT INTO events (event_id, event_type, person_id, payload, occurred_at, recorded_at)
                 VALUES (?, ?, ?, ?, ?, ?)",
                [
                  decision_id,
                  "DecisionRecorded",
                  person_id,
                  JSON.generate(payload),
                  Clock.iso8601(at),
                  Clock.iso8601(Clock.now)
                ]
              )
              db.commit

              Domain::DecisionResult.new(
                person_id: person_id,
                supporter_id: supporter_id,
                scope: scope,
                decision_at: at,
                seen_sequence: seen,
                reason_code: result.reason_code,
                chain: result.chain,
                emergency: result.emergency,
                decision_id: decision_id
              )
            end
        end
      end

      def all_events
        @mutex.synchronize { with_db { |db| read_events(db) } }
      end

      def events_up_to(sequence)
        @mutex.synchronize do
          with_db do |db|
            db.execute(
              "SELECT sequence, event_id, event_type, person_id, payload, occurred_at, recorded_at
               FROM events WHERE sequence <= ? ORDER BY sequence ASC",
              [sequence]
            ).map { |row| row_to_event(row) }
          end
        end
      end

      def find_event(sequence)
        @mutex.synchronize do
          with_db { |db| read_event(db, sequence) }
        end
      end

      def find_decision(decision_id)
        @mutex.synchronize do
          with_db do |db|
            row = db.execute(
              "SELECT sequence, event_id, event_type, person_id, payload, occurred_at, recorded_at
               FROM events WHERE event_id = ? AND event_type = 'DecisionRecorded'",
              [decision_id]
            ).first
            row_to_event(row) if row
          end
        end
      end

      def verify_replay(decision_id)
        decision = find_decision(decision_id)
        return nil unless decision

        seen = decision.payload["seenSequence"]
        events = events_up_to(seen)
        request = {
          person_id: decision.person_id,
          supporter_id: decision.payload["supporterId"],
          scope: decision.payload["scope"],
          at: Clock.parse_time(decision.payload["decisionAt"])
        }
        snap = decision.payload["policySnapshot"]
        policy = if snap
          Domain::EmergencyPolicy.new(
            allowed_scope: snap["allowedScope"],
            max_minutes: snap["maxMinutes"],
            requires_review_event: snap["requiresReviewEvent"]
          )
        end
        recomputed = Domain::ConsentBoundary.evaluate(events, request, policy)

        recorded_chain = decision.payload["chain"] || []
        recomputed_chain = recomputed.chain.map(&:as_json)
        {
          decision_id: decision_id,
          decision_sequence: decision.sequence,
          seen_sequence: seen,
          recorded_reason_code: decision.payload["reasonCode"],
          recomputed_reason_code: recomputed.reason_code,
          reason_code_matches: decision.payload["reasonCode"] == recomputed.reason_code,
          recorded_chain: recorded_chain,
          recomputed_chain: recomputed_chain,
          chain_matches: JSON.generate(recorded_chain) == JSON.generate(recomputed_chain)
        }
      end

      def reset!
        @mutex.synchronize do
          with_db do |db|
            db.execute("DROP TRIGGER IF EXISTS events_no_update")
            db.execute("DROP TRIGGER IF EXISTS events_no_delete")
            db.execute("DELETE FROM events")
            db.execute("DELETE FROM sqlite_sequence WHERE name = 'events'")
          end
          setup_schema
        end
      end

      private

      def setup_schema
        with_db do |db|
          db.execute <<~SQL
            CREATE TABLE IF NOT EXISTS events (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT,
              event_id TEXT NOT NULL UNIQUE,
              event_type TEXT NOT NULL,
              person_id TEXT,
              payload TEXT NOT NULL,
              occurred_at TEXT NOT NULL,
              recorded_at TEXT NOT NULL
            )
          SQL
          db.execute("CREATE INDEX IF NOT EXISTS idx_events_person ON events(person_id)")
          db.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
          db.execute("CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id)")

          db.execute <<~SQL
            CREATE TRIGGER IF NOT EXISTS events_no_update
            BEFORE UPDATE ON events
            BEGIN
              SELECT RAISE(FAIL, 'events are append-only and immutable');
            END
          SQL
          db.execute <<~SQL
            CREATE TRIGGER IF NOT EXISTS events_no_delete
            BEFORE DELETE ON events
            BEGIN
              SELECT RAISE(FAIL, 'events are append-only and immutable');
            END
          SQL
        end
      end

      def with_db
        db = SQLite3::Database.new(@db_path, results_as_hash: true)
        begin
          yield db
        ensure
          db.close
        end
      end

      def read_events(db)
        db.execute(
          "SELECT sequence, event_id, event_type, person_id, payload, occurred_at, recorded_at
           FROM events ORDER BY sequence ASC"
        ).map { |row| row_to_event(row) }
      end

      def read_event(db, sequence)
        row = db.execute(
          "SELECT sequence, event_id, event_type, person_id, payload, occurred_at, recorded_at
           FROM events WHERE sequence = ?",
          [sequence]
        ).first
        row_to_event(row) if row
      end

      def row_to_event(row)
        Domain::AuditEvent.new(
          sequence: row["sequence"],
          event_id: row["event_id"],
          type: row["event_type"],
          person_id: row["person_id"],
          payload: JSON.parse(row["payload"]),
          occurred_at: Clock.parse_time(row["occurred_at"]),
          recorded_at: Clock.parse_time(row["recorded_at"])
        )
      end
    end
  end
end
