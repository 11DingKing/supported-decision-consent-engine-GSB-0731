# frozen_string_literal: true

$LOAD_PATH.unshift(File.expand_path("lib", __dir__))

require "consent"
require "consent/api"
require "fileutils"

# Native entrypoint: `bundle exec ruby app.rb`.
#
# Boots the append-only event store, seeds it from the authoritative material
# (only when empty, so restarts stay deterministic and never duplicate facts),
# and mounts the thin Sinatra API. All authorization judgement stays in the
# pure domain objects under lib/consent.
db_path = ENV.fetch("CONSENT_DB", File.expand_path("db/consent.sqlite3", __dir__))
FileUtils.mkdir_p(File.dirname(db_path))

store = Consent::EventStore.new(db_path)
ledger = Consent::Ledger.new(store)

seed_path = File.expand_path("materials/consent-cases.json", __dir__)
if (store.max_seq || 0).zero? && File.exist?(seed_path)
  Consent::Seed.load_file(ledger, seed_path)
  warn "[consent] seeded #{ledger.max_seq} events from #{seed_path}"
end

app = Consent::API.for_ledger(ledger)

port = ENV.fetch("PORT", "4567").to_i
warn "[consent] listening on http://127.0.0.1:#{port} (events=#{ledger.max_seq || 0})"

app.set :bind, "127.0.0.1"
app.set :port, port
app.run!
