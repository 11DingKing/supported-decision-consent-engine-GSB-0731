# frozen_string_literal: true

require "sqlite3"
require "json"
require_relative "event"
require_relative "canonical_json"

module Consent
  # Append-only, tamper-evident event store on SQLite.
  #
  # Responsibilities (deliberately narrow — NO authorization logic here):
  #   * Assign a monotonic audit seq to every appended fact.
  #   * Maintain a SHA-256 hash chain (each event binds the previous hash).
  #   * Physically forbid UPDATE and DELETE on the events table via triggers,
  #     so history is immutable and cannot be silently rewritten.
  #   * Serialize appends so concurrent grant/revoke submissions get distinct,
  #     ordered seqs and a single consistent chain.
  #
  # The store never interprets whether a fact authorizes anything. It hands raw
  # Event objects to the domain, which decides. This is what keeps a race from
  # widening scope: concurrency only affects the ORDER facts are recorded, and
  # each decision pins the max seq it may see.
  class EventStore
    class TamperError < StandardError; end
    class AppendError < StandardError; end

    attr_reader :path

    def initialize(path)
      @path = path
      @db = SQLite3::Database.new(path.to_s)
      @db.busy_timeout = 5000
      @db.results_as_hash = true
      configure
      migrate
    end

    def configure
      @db.execute("PRAGMA journal_mode=WAL")
      @db.execute("PRAGMA synchronous=FULL")
      @db.execute("PRAGMA foreign_keys=ON")
    end

    def migrate
      @db.execute_batch(<<~SQL)
        CREATE TABLE IF NOT EXISTS events (
          seq         INTEGER PRIMARY KEY AUTOINCREMENT,
          type        TEXT NOT NULL,
          event_time  TEXT NOT NULL,
          payload     TEXT NOT NULL,
          recorded_at TEXT NOT NULL,
          prev_hash   TEXT,
          hash        TEXT NOT NULL UNIQUE,
          request_id  TEXT
        );

        -- Idempotency: a client-supplied request_id may appear at most once, so
        -- a resubmitted decision or command collapses onto the original fact
        -- instead of appending a duplicate (which could reset budgets or shift
        -- the audit boundary). NULL request_ids are unconstrained.
        CREATE UNIQUE INDEX IF NOT EXISTS events_request_id_uniq
          ON events (request_id) WHERE request_id IS NOT NULL;

        -- Immutability guards: recorded facts can never be altered or removed.
        CREATE TRIGGER IF NOT EXISTS events_no_update
        BEFORE UPDATE ON events
        BEGIN
          SELECT RAISE(ABORT, 'events are immutable: update forbidden');
        END;

        CREATE TRIGGER IF NOT EXISTS events_no_delete
        BEFORE DELETE ON events
        BEGIN
          SELECT RAISE(ABORT, 'events are immutable: delete forbidden');
        END;
      SQL
    end

    # Append a fact atomically. Returns the persisted Event (with seq + hash).
    # The whole read-tip/compute-hash/insert sequence runs inside an IMMEDIATE
    # transaction so concurrent writers cannot interleave and fork the chain.
    #
    # When `request_id` is given the append is IDEMPOTENT: if a fact with that
    # id was already recorded, the original Event is returned unchanged and no
    # new fact is appended. This is what makes a duplicated submission a no-op —
    # it can neither widen scope, reset an emergency budget, nor move the audit
    # seq boundary.
    def append(type:, event_time:, payload: {}, recorded_at: nil, request_id: nil)
      recorded_at ||= Time.now.utc
      persisted = nil

      transaction do
        if request_id && (existing = find_by_request_id(request_id))
          persisted = build_event(existing)
        else
          tip = current_tip
          prev_hash = tip && tip["hash"]
          next_seq = (tip && tip["seq"]).to_i + 1

          event = Event.new(
            seq: next_seq,
            type: type,
            event_time: event_time,
            payload: payload,
            recorded_at: recorded_at,
            prev_hash: prev_hash
          )

          @db.execute(
            "INSERT INTO events (seq, type, event_time, payload, recorded_at, prev_hash, hash, request_id) " \
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
              event.seq,
              event.type,
              event.event_time.iso8601,
              CanonicalJSON.dump(event.payload),
              event.recorded_at.iso8601,
              event.prev_hash,
              event.hash_value,
              request_id
            ]
          )
          persisted = event
        end
      end

      persisted
    rescue SQLite3::ConstraintException => e
      raise AppendError, "append failed: #{e.message}"
    end

    # Load all events (optionally up to and including max_seq) as Event objects,
    # verifying the hash chain as we go. Any break raises TamperError.
    def load_events(max_seq: nil)
      rows =
        if max_seq
          @db.execute("SELECT * FROM events WHERE seq <= ? ORDER BY seq ASC", [max_seq])
        else
          @db.execute("SELECT * FROM events ORDER BY seq ASC")
        end

      prev_hash = nil
      rows.map do |row|
        event = build_event(row)
        unless event.valid_hash? && event.prev_hash == prev_hash
          raise TamperError, "hash chain broken at seq #{event.seq}"
        end

        prev_hash = event.hash_value
        event
      end
    end

    def max_seq
      row = @db.get_first_row("SELECT MAX(seq) AS m FROM events")
      row && row["m"]
    end

    def count
      @db.get_first_value("SELECT COUNT(*) FROM events").to_i
    end

    # Return the already-recorded Event for a request_id, or nil. Lets callers
    # detect a resubmission and reproduce the original outcome without writing.
    def event_for_request(request_id)
      return nil if request_id.nil?

      row = find_by_request_id(request_id)
      row && build_event(row)
    end

    def close
      @db.close
    end

    private

    def build_event(row)
      Event.new(
        seq: row["seq"],
        type: row["type"],
        event_time: row["event_time"],
        payload: JSON.parse(row["payload"]),
        recorded_at: row["recorded_at"],
        prev_hash: row["prev_hash"],
        hash_value: row["hash"]
      )
    end

    def find_by_request_id(request_id)
      @db.get_first_row("SELECT * FROM events WHERE request_id = ? LIMIT 1", [request_id])
    end

    def current_tip
      @db.get_first_row("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1")
    end

    def transaction
      @db.transaction(:immediate) { yield }
    end
  end
end
