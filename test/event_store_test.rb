# frozen_string_literal: true

require_relative "test_helper"

# The audit log is the source of truth for "what was recorded". These tests
# assert it is physically append-only and tamper-evident: no UPDATE, no DELETE,
# a monotonic seq, and a SHA-256 hash chain that detects any post-hoc edit.
class EventStoreTest < Minitest::Test
  include TestSupport

  def store
    @store ||= begin
      dir = Dir.mktmpdir("consent-store")
      @stores ||= []
      s = Consent::EventStore.new(File.join(dir, "store.sqlite3"))
      @stores << s
      s
    end
  end

  def test_append_assigns_monotonic_seq_and_chain
    e1 = store.append(type: "SCOPE_DEFINED", event_time: "2026-01-01T00:00:00Z", payload: { "scope" => "A" })
    e2 = store.append(type: "SCOPE_DEFINED", event_time: "2026-01-02T00:00:00Z", payload: { "scope" => "B" })
    assert_equal 1, e1.seq
    assert_equal 2, e2.seq
    assert_nil e1.prev_hash
    assert_equal e1.hash_value, e2.prev_hash
  end

  def test_update_is_forbidden_by_trigger
    store.append(type: "SCOPE_DEFINED", event_time: "2026-01-01T00:00:00Z", payload: { "scope" => "A" })
    db = SQLite3::Database.new(store.path.to_s)
    err = assert_raises(SQLite3::ConstraintException) do
      db.execute("UPDATE events SET payload = '{}' WHERE seq = 1")
    end
    assert_match(/immutable/, err.message)
  ensure
    db&.close
  end

  def test_delete_is_forbidden_by_trigger
    store.append(type: "SCOPE_DEFINED", event_time: "2026-01-01T00:00:00Z", payload: { "scope" => "A" })
    db = SQLite3::Database.new(store.path.to_s)
    err = assert_raises(SQLite3::ConstraintException) do
      db.execute("DELETE FROM events WHERE seq = 1")
    end
    assert_match(/immutable/, err.message)
  ensure
    db&.close
  end

  def test_load_verifies_hash_chain
    store.append(type: "SCOPE_DEFINED", event_time: "2026-01-01T00:00:00Z", payload: { "scope" => "A" })
    store.append(type: "SCOPE_DEFINED", event_time: "2026-01-02T00:00:00Z", payload: { "scope" => "B" })
    events = store.load_events
    assert_equal 2, events.length
    assert(events.all?(&:valid_hash?))
  end
end
