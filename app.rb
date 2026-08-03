# frozen_string_literal: true

require "json"
require_relative "lib/consent_engine"
require_relative "lib/consent_engine/sqlite_event_store"
require_relative "lib/web"

# Build the service backed by SQLite, bootstrapped from the authoritative
# cases file when the database is empty.
DB_PATH = ENV.fetch("CONSENT_DB_PATH", File.expand_path("consent.db", __dir__))
CASES_PATH = File.expand_path("materials/consent-cases.json", __dir__)

store = ConsentEngine::SQLiteEventStore.new(DB_PATH)
emergency_data = JSON.parse(File.read(CASES_PATH)).fetch("emergency", {})

SERVICE = ConsentEngine::Service.new(
  store: store,
  emergency_config: {
    allowed_scope: emergency_data["allowedScope"],
    max_minutes: emergency_data["maxMinutes"] || 30,
    requires_review_event: emergency_data["requiresReviewEvent"]
  }
)

# Bootstrap from the authoritative cases file if the DB is empty. We do this
# at startup so a fresh `ruby app.rb` immediately reflects the baseline.
if store.high_seq.zero? && File.exist?(CASES_PATH)
  data = JSON.parse(File.read(CASES_PATH))
  SERVICE.register_person(data["personId"])
  Array(data["supporters"]).each { |s| SERVICE.register_supporter(s) }

  Array(data["consents"]).each do |c|
    SERVICE.grant_consent(
      consent_id: c["id"],
      person_id: data["personId"],
      supporter_id: c["supporterId"],
      scopes: c["scopes"],
      from: c["from"],
      to: c["to"],
      witness_id: c["witnessId"],
      effective_at: c["from"]
    )
  end

  Array(data["delegations"]).each do |d|
    SERVICE.delegate(
      delegation_id: d["id"],
      source_consent_id: d["sourceConsentId"],
      from_supporter_id: d["fromSupporterId"],
      to_supporter_id: d["toSupporterId"],
      scopes: d["scopes"],
      to: d["to"],
      effective_at: d["from"]
    )
  end

  Array(data["revocations"]).each do |r|
    SERVICE.revoke_consent(
      revocation_id: r["id"],
      consent_id: r["consentId"],
      at: r["at"],
      effective_at: r["at"]
    )
  end
end

ConsentEngine::Web.set :service, SERVICE
ConsentEngine::Web.run! if __FILE__ == $PROGRAM_NAME
