$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "minitest/autorun"
require "tmpdir"
require "fileutils"
require "json"
require "consent_engine"

module TestHelpers
  def fresh_store
    path = File.join(@tmpdir, "test-#{SecureRandom.hex(4)}.db")
    ConsentEngine::Persistence::SqliteEventStore.new(path)
  end

  def default_policy
    ConsentEngine::Domain::EmergencyPolicy.new(
      allowed_scope: "LEGAL_AID_APPLICATION",
      max_minutes: 30,
      requires_review_event: true
    )
  end

  def t(str)
    Time.iso8601(str).utc
  end

  def seed_authoritative(store)
    ConsentEngine::SeedLoader.load(
      store,
      File.expand_path("../materials/consent-cases.json", __dir__)
    )
  end

  def grant_consent(store, consent_id:, supporter:, scopes:, from:, to:, witness: "W-1", person: "PERSON-01", occurred_at: nil)
    store.append(
      event_type: "ConsentGranted",
      event_id: consent_id,
      person_id: person,
      occurred_at: occurred_at || from,
      payload: {
        "consentId" => consent_id,
        "supporterId" => supporter,
        "scopes" => Array(scopes),
        "validFrom" => from,
        "validTo" => to,
        "witnessId" => witness
      }
    )
  end

  def delegate(store, delegation_id:, source_consent:, from_sup:, to_sup:, scopes:, occurred_at:, valid_to: nil, emergency_budget_minutes: nil, person: "PERSON-01")
    store.append(
      event_type: "DelegationGranted",
      event_id: delegation_id,
      person_id: person,
      occurred_at: occurred_at,
      payload: {
        "delegationId" => delegation_id,
        "sourceConsentId" => source_consent,
        "fromSupporterId" => from_sup,
        "toSupporterId" => to_sup,
        "scopes" => Array(scopes),
        "validTo" => valid_to,
        "emergencyBudgetMinutes" => emergency_budget_minutes
      }
    )
  end

  def revoke_consent(store, revocation_id:, consent_id:, at:, person: "PERSON-01")
    store.append(
      event_type: "ConsentRevoked",
      event_id: revocation_id,
      person_id: person,
      occurred_at: at,
      payload: { "revocationId" => revocation_id, "consentId" => consent_id }
    )
  end

  def revoke_delegation(store, revocation_id:, delegation_id:, at:, person: "PERSON-01")
    store.append(
      event_type: "DelegationRevoked",
      event_id: revocation_id,
      person_id: person,
      occurred_at: at,
      payload: { "delegationId" => delegation_id }
    )
  end

  def start_emergency(store, emergency_id:, scope:, started_at:, supporter: nil, person: "PERSON-01", source_consent_id: nil, consumed_minutes: nil)
    store.append(
      event_type: "EmergencyAccessStarted",
      event_id: emergency_id,
      person_id: person,
      occurred_at: started_at,
      payload: {
        "emergencyId" => emergency_id,
        "scope" => scope,
        "supporterId" => supporter,
        "sourceConsentId" => source_consent_id,
        "consumedMinutes" => consumed_minutes
      }
    )
  end

  def review_emergency(store, emergency_id:, reviewed_at:, person: "PERSON-01")
    store.append(
      event_type: "EmergencyReviewRecorded",
      event_id: "REV-#{emergency_id}",
      person_id: person,
      occurred_at: reviewed_at,
      payload: { "emergencyId" => emergency_id }
    )
  end
end

class Minitest::Test
  include TestHelpers

  def setup
    @tmpdir = Dir.mktmpdir("consent-engine-test")
  end

  def teardown
    FileUtils.remove_entry(@tmpdir) if @tmpdir && Dir.exist?(@tmpdir)
  end
end
