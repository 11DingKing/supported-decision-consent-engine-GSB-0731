# frozen_string_literal: true

require "json"
require_relative "consent_engine/reason_codes"
require_relative "consent_engine/event"
require_relative "consent_engine/authorization_decision"
require_relative "consent_engine/event_store"
require_relative "consent_engine/authorizer"
require_relative "consent_engine/service"

module ConsentEngine
  # Loads the authoritative cases from materials/consent-cases.json into a
  # Service and returns it. Pure helper — no I/O magic outside the file read.
  def self.build_from_cases(path)
    data = JSON.parse(File.read(path))

    store = EventStore.new
    emergency = data["emergency"] || {}
    service = Service.new(
      store: store,
      emergency_config: {
        allowed_scope: emergency["allowedScope"],
        max_minutes: emergency["maxMinutes"] || 30,
        requires_review_event: emergency["requiresReviewEvent"]
      }
    )

    service.register_person(data["personId"])
    Array(data["supporters"]).each { |s| service.register_supporter(s) }

    Array(data["consents"]).each do |c|
      service.grant_consent(
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
      service.delegate(
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
      service.revoke_consent(
        revocation_id: r["id"],
        consent_id: r["consentId"],
        at: r["at"],
        effective_at: r["at"]
      )
    end

    service
  end
end
