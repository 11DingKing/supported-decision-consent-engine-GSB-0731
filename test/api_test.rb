require_relative "test_helper"
require "rack/test"

class ApiTest < Minitest::Test
  include Rack::Test::Methods

  def app
    ConsentEngine::Api::Server
  end

  def setup
    super
    @store = fresh_store
    ConsentEngine::Api::Server.set :store, @store
    ConsentEngine::Api::Server.set :policy, default_policy
  end

  def json_post(path, body)
    post path, body.to_json, { "CONTENT_TYPE" => "application/json" }
  end

  def parsed
    JSON.parse(last_response.body)
  end

  def test_health
    get "/health"
    assert last_response.ok?
    assert_equal "ok", parsed["status"]
  end

  def test_grant_consent_and_evaluate_authorized
    json_post "/people/PERSON-01/consents", {
      "supporterId" => "SUPPORTER-A",
      "scopes" => ["LEGAL_AID_APPLICATION"],
      "validFrom" => "2026-08-01T00:00:00Z",
      "validTo" => "2026-12-01T00:00:00Z",
      "witnessId" => "W-1"
    }
    assert_equal 201, last_response.status
    assert_equal "ConsentGranted", parsed["type"]

    json_post "/decisions", {
      "personId" => "PERSON-01",
      "supporterId" => "SUPPORTER-A",
      "scope" => "LEGAL_AID_APPLICATION",
      "at" => "2026-09-01T00:00:00Z"
    }
    assert last_response.ok?
    assert parsed["authorized"]
    assert_equal "AUTHORIZED", parsed["reasonCode"]
    assert_equal 1, parsed["seenSequence"]
    assert_equal 1, parsed["chain"].length
    assert parsed["decisionId"]
  end

  def test_silence_returns_no_consent_via_http
    json_post "/decisions", {
      "personId" => "PERSON-01",
      "supporterId" => "UNKNOWN",
      "scope" => "LEGAL_AID_APPLICATION",
      "at" => "2026-09-01T00:00:00Z"
    }
    refute parsed["authorized"]
    assert_equal "NO_CONSENT", parsed["reasonCode"]
  end

  def test_revocation_endpoint_then_decision_is_revoked
    json_post "/people/PERSON-01/consents", {
      "id" => "C1",
      "supporterId" => "A",
      "scopes" => ["HOUSING_APPLICATION"],
      "validFrom" => "2026-08-01T00:00:00Z",
      "validTo" => "2026-12-01T00:00:00Z",
      "witnessId" => "W-1"
    }

    json_post "/consents/C1/revocations", {
      "id" => "R1",
      "at" => "2026-09-15T10:00:00Z"
    }
    assert_equal 201, last_response.status
    assert_equal "ConsentRevoked", parsed["type"]

    json_post "/decisions", {
      "personId" => "PERSON-01",
      "supporterId" => "A",
      "scope" => "HOUSING_APPLICATION",
      "at" => "2026-09-16T00:00:00Z"
    }
    refute parsed["authorized"]
    assert_equal "REVOKED", parsed["reasonCode"]
  end

  def test_delegation_endpoint_to_endpoint
    json_post "/people/PERSON-01/consents", {
      "id" => "C1",
      "supporterId" => "A",
      "scopes" => ["LEGAL_AID_APPLICATION", "HOUSING_APPLICATION"],
      "validFrom" => "2026-08-01T00:00:00Z",
      "validTo" => "2026-12-01T00:00:00Z",
      "witnessId" => "W-1"
    }

    json_post "/consents/C1/delegations", {
      "id" => "D1",
      "fromSupporterId" => "A",
      "toSupporterId" => "B",
      "scopes" => ["LEGAL_AID_APPLICATION"],
      "occurredAt" => "2026-08-02T00:00:00Z",
      "validTo" => "2026-11-01T00:00:00Z"
    }
    assert_equal 201, last_response.status

    json_post "/decisions", {
      "personId" => "PERSON-01",
      "supporterId" => "B",
      "scope" => "LEGAL_AID_APPLICATION",
      "at" => "2026-09-01T00:00:00Z"
    }
    assert parsed["authorized"]
    assert_equal ["C1", "D1"], parsed["chain"].map { |l| l["id"] }
  end

  def test_broad_delegation_rejected_over_http
    json_post "/people/PERSON-01/consents", {
      "id" => "C1",
      "supporterId" => "A",
      "scopes" => ["LEGAL_AID_APPLICATION"],
      "validFrom" => "2026-08-01T00:00:00Z",
      "validTo" => "2026-12-01T00:00:00Z",
      "witnessId" => "W-1"
    }
    json_post "/consents/C1/delegations", {
      "id" => "DBROAD",
      "fromSupporterId" => "A",
      "toSupporterId" => "B",
      "scopes" => ["MEDICAL_INFORMATION_VIEW"],
      "occurredAt" => "2026-08-02T00:00:00Z"
    }

    json_post "/decisions", {
      "personId" => "PERSON-01",
      "supporterId" => "B",
      "scope" => "MEDICAL_INFORMATION_VIEW",
      "at" => "2026-09-01T00:00:00Z"
    }
    refute parsed["authorized"]
    assert_equal "DELEGATION_BROADER_THAN_SOURCE", parsed["reasonCode"]
  end

  def test_emergency_flow_over_http
    json_post "/emergencies", {
      "id" => "E1",
      "scope" => "LEGAL_AID_APPLICATION",
      "startedAt" => "2026-09-01T10:00:00Z"
    }
    assert_equal 201, last_response.status

    json_post "/decisions", {
      "personId" => "PERSON-01",
      "supporterId" => "ANY",
      "scope" => "LEGAL_AID_APPLICATION",
      "at" => "2026-09-01T10:15:00Z"
    }
    assert parsed["authorized"]
    assert_equal "EMERGENCY_AUTHORIZED", parsed["reasonCode"]

    json_post "/emergencies/E1/review", {
      "reviewedAt" => "2026-09-01T10:20:00Z"
    }
    assert_equal 201, last_response.status

    json_post "/decisions", {
      "personId" => "PERSON-01",
      "supporterId" => "ANY",
      "scope" => "LEGAL_AID_APPLICATION",
      "at" => "2026-09-01T10:31:00Z"
    }
    refute parsed["authorized"]
    assert_equal "EMERGENCY_TIMEOUT", parsed["reasonCode"]
  end

  def test_events_listing
    json_post "/people/PERSON-01/consents", {
      "supporterId" => "A",
      "scopes" => ["HOUSING_APPLICATION"],
      "validFrom" => "2026-08-01T00:00:00Z",
      "validTo" => "2026-12-01T00:00:00Z",
      "witnessId" => "W-1"
    }
    get "/events"
    assert last_response.ok?
    assert_equal 1, parsed["events"].length
    assert_equal 1, parsed["events"].first["sequence"]
  end

  def test_decision_verify_endpoint
    json_post "/people/PERSON-01/consents", {
      "id" => "C1",
      "supporterId" => "A",
      "scopes" => ["LEGAL_AID_APPLICATION"],
      "validFrom" => "2026-08-01T00:00:00Z",
      "validTo" => "2026-12-01T00:00:00Z",
      "witnessId" => "W-1"
    }
    json_post "/decisions", {
      "personId" => "PERSON-01",
      "supporterId" => "A",
      "scope" => "LEGAL_AID_APPLICATION",
      "at" => "2026-09-01T00:00:00Z"
    }
    decision_id = parsed["decisionId"]

    get "/decisions/#{decision_id}/verify"
    assert last_response.ok?
    assert parsed["reason_code_matches"]
    assert parsed["chain_matches"]
  end

  def test_missing_fields_returns_422
    json_post "/people/PERSON-01/consents", { "supporterId" => "A" }
    assert_equal 422, last_response.status
    assert parsed["fields"].include?("scopes")
  end
end
