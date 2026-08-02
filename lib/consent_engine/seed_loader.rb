require "json"
require_relative "clock"

module ConsentEngine
  class SeedLoader
    def self.load(store, path)
      data = JSON.parse(File.read(path))
      person_id = data["personId"]

      data.fetch("consents", []).each do |c|
        store.append(
          event_type: "ConsentGranted",
          event_id: c["id"],
          person_id: person_id,
          occurred_at: c["from"],
          payload: {
            "consentId" => c["id"],
            "supporterId" => c["supporterId"],
            "scopes" => c["scopes"],
            "validFrom" => c["from"],
            "validTo" => c["to"],
            "witnessId" => c["witnessId"]
          }
        )
      end

      data.fetch("delegations", []).each do |d|
        source = data["consents"].find { |c| c["id"] == d["sourceConsentId"] }
        store.append(
          event_type: "DelegationGranted",
          event_id: d["id"],
          person_id: person_id,
          occurred_at: source ? source["from"] : Clock.now,
          payload: {
            "delegationId" => d["id"],
            "sourceConsentId" => d["sourceConsentId"],
            "fromSupporterId" => d["fromSupporterId"],
            "toSupporterId" => d["toSupporterId"],
            "scopes" => d["scopes"],
            "validTo" => d["to"]
          }
        )
      end

      data.fetch("revocations", []).each do |r|
        store.append(
          event_type: "ConsentRevoked",
          event_id: r["id"],
          person_id: person_id,
          occurred_at: r["at"],
          payload: {
            "revocationId" => r["id"],
            "consentId" => r["consentId"]
          }
        )
      end

      data
    end
  end
end
