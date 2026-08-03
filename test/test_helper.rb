# frozen_string_literal: true

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "minitest/autorun"
require "tmpdir"
require "securerandom"
require "consent"

module TestSupport
  # Fresh, isolated event store per test in a temp dir. Keeps runs hermetic and
  # avoids touching the seeded db/ store.
  def fresh_ledger
    dir = Dir.mktmpdir("consent-test")
    path = File.join(dir, "#{SecureRandom.hex(6)}.sqlite3")
    store = Consent::EventStore.new(path)
    @stores ||= []
    @stores << store
    Consent::Ledger.new(store)
  end

  def seeded_ledger
    ledger = fresh_ledger
    Consent::Seed.load_file(ledger, File.expand_path("../materials/consent-cases.json", __dir__))
    ledger
  end

  def teardown
    Array(@stores).each { |s| s.close rescue nil }
  end
end
