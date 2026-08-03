# frozen_string_literal: true

require "sqlite3"
require "json"
require_relative "event"

module ConsentEngine
  # SQLite-backed append-only event store.
  #
  # Design:
  #   * +seq+ is INTEGER PRIMARY KEY AUTOINCREMENT — SQLite assigns it
  #     atomically inside an IMMEDIATE transaction, so two concurrent writers
  #     cannot share a seq and no race can insert a new event *between* a
  #     reader's snapshot high-water mark and its use.
  #   * +event_id+ has a UNIQUE index so the same logical event cannot be
  #     double-applied by a retry.
  #   * No row is ever UPDATEd or DELETEd — the table is INSERT-only, which
  #     gives us immutable history that can be replayed.
  #   * Authorization is performed against a snapshot taken with
  #     seq <= ? inside a read transaction, so decisions see a consistent
  #     prefix of the log.
  class SQLiteEventStore
    class DuplicateEventId < StandardError; end

    SCHEMA = <<~SQL
      CREATE TABLE IF NOT EXISTS audit_events (
        seq           INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id      TEXT NOT NULL UNIQUE,
        type          TEXT NOT NULL,
        observed_at   TEXT NOT NULL,
        effective_at  TEXT NOT NULL,
        payload       TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(type);
      CREATE INDEX IF NOT EXISTS idx_audit_effective ON audit_events(effective_at);
    SQL

    attr_reader :db, :clock

    def initialize(path = ":memory:")
      @db = SQLite3::Database.new(path)
      @db.results_as_hash = true
      @db.execute(SCHEMA)
      @clock = -> { Time.now.utc }
    end

    def clock=(callable)
      @clock = callable
    end

    def append(event_id:, type:, payload:, effective_at: nil)
      observed = @clock.call
      effective = effective_at ? coerce_time(effective_at) : observed
      payload_json = JSON.generate(payload)

      @db.execute("BEGIN IMMEDIATE")
      begin
        @db.execute(
          "INSERT INTO audit_events (event_id, type, observed_at, effective_at, payload) VALUES (?, ?, ?, ?, ?)",
          [event_id, type, observed.utc.iso8601, effective.utc.iso8601, payload_json]
        )
        seq = @db.last_insert_row_id
        @db.execute("COMMIT")

        Event.new(
          seq: seq,
          event_id: event_id,
          type: type,
          observed_at: observed,
          effective_at: effective,
          payload: payload
        )
      rescue SQLite3::ConstraintException => e
        @db.execute("ROLLBACK") rescue nil
        if e.message.include?("UNIQUE") && e.message.include?("event_id")
          raise DuplicateEventId, "event_id=#{event_id} already exists"
        end
        raise
      rescue => e
        @db.execute("ROLLBACK") rescue nil
        raise
      end
    end

    def snapshot(seen_seq: nil)
      @db.execute("BEGIN")
      begin
        max = seen_seq || high_seq_unsafe
        rows = @db.execute(
          "SELECT seq, event_id, type, observed_at, effective_at, payload FROM audit_events WHERE seq <= ? ORDER BY seq ASC",
          [max]
        )
        @db.execute("COMMIT")
        rows.map { |r| row_to_event(r) }
      rescue
        @db.execute("ROLLBACK") rescue nil
        raise
      end
    end

    def high_seq
      @db.execute("BEGIN")
      begin
        v = high_seq_unsafe
        @db.execute("COMMIT")
        v
      rescue
        @db.execute("ROLLBACK") rescue nil
        raise
      end
    end

    def all
      snapshot
    end

    def find_event(event_id)
      row = @db.get_first_row(
        "SELECT seq, event_id, type, observed_at, effective_at, payload FROM audit_events WHERE event_id = ?",
        [event_id]
      )
      return nil unless row
      row_to_event(row)
    end

    def reset!
      @db.execute("DELETE FROM audit_events")
      @db.execute("DELETE FROM sqlite_sequence WHERE name='audit_events'")
    end

    def close
      @db.close
    end

    private

    def coerce_time(t)
      return t if t.is_a?(Time)
      Time.iso8601(t.to_s)
    end

    def high_seq_unsafe
      row = @db.get_first_row("SELECT COALESCE(MAX(seq), 0) FROM audit_events")
      row.is_a?(Hash) ? row.values.first.to_i : row.first.to_i
    end

    def row_to_event(row)
      payload =
        case row["payload"]
        when String then JSON.parse(row["payload"])
        else row["payload"]
        end
      Event.new(
        seq: row["seq"].to_i,
        event_id: row["event_id"],
        type: row["type"],
        observed_at: row["observed_at"],
        effective_at: row["effective_at"],
        payload: payload
      )
    end
  end
end
