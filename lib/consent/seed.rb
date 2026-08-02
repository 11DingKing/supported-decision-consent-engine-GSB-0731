# frozen_string_literal: true

require "json"

module Consent
  # Loads the authoritative fixture (materials/consent-cases.json) into a
  # ledger as a sequence of recorded facts. Identifiers come straight from the
  # material, which the README declares authoritative. This is fact-recording
  # only — it never pre-judges authority.
  module Seed
    module_function

    def load_file(ledger, path)
      data = JSON.parse(File.read(path))
      load_data(ledger, data)
    end

    def load_data(ledger, data)
      ledger.register_person(data["personId"]) if data["personId"]

      Array(data["scopes"]).each { |s| ledger.define_scope(s) }
      Array(data["supporters"]).each { |s| ledger.add_supporter(s) }

      Array(data["consents"]).each do |c|
        ledger.grant_consent(
          id: c["id"],
          supporter_id: c["supporterId"],
          scopes: c["scopes"],
          from: c["from"],
          to: c["to"],
          witness_id: c["witnessId"]
        )
      end

      Array(data["delegations"]).each do |d|
        ledger.create_delegation(
          id: d["id"],
          source_consent_id: d["sourceConsentId"],
          from_supporter_id: d["fromSupporterId"],
          to_supporter_id: d["toSupporterId"],
          scopes: d["scopes"],
          from: d["from"],
          to: d["to"]
        )
      end

      if (emg = data["emergency"])
        ledger.set_emergency_policy(
          allowed_scope: emg["allowedScope"],
          max_minutes: emg["maxMinutes"],
          requires_review_event: emg["requiresReviewEvent"]
        )
      end

      Array(data["revocations"]).each do |r|
        ledger.revoke_consent(consent_id: r["consentId"], at: r["at"])
      end

      ledger
    end
  end
end
