# frozen_string_literal: true

require_relative "test_helper"
require "rack/test"
require "consent/api"

# The HTTP layer is a thin adapter: it must faithfully surface the domain's
# decisions and never make its own authorization judgement. These tests drive
# the API end-to-end over rack-test.
class ApiTest < Minitest::Test
  include TestSupport
  include Rack::Test::Methods

  def app
    @app ||= Consent::API.for_ledger(seeded_ledger)
  end

  def post_json(path, body)
    post path, JSON.generate(body), "CONTENT_TYPE" => "application/json"
    JSON.parse(last_response.body)
  end

  def test_health
    get "/health"
    assert_equal 200, last_response.status
    body = JSON.parse(last_response.body)
    assert_equal "ok", body["status"]
  end

  def test_decision_direct_consent
    body = post_json("/decisions",
      { "supporterId" => "SUPPORTER-A", "scope" => "LEGAL_AID_APPLICATION",
        "at" => "2026-09-01T00:00:00Z" })
    assert_equal 200, last_response.status
    assert_equal true, body["authorized"]
    assert_equal "AUTHORIZED_DIRECT_CONSENT", body["reasonCode"]
    assert body["asOfSeq"].is_a?(Integer)
  end

  def test_decision_at_exact_revocation_instant
    body = post_json("/decisions",
      { "supporterId" => "SUPPORTER-A", "scope" => "LEGAL_AID_APPLICATION",
        "at" => "2026-09-15T10:00:00Z", "record" => false })
    assert_equal false, body["authorized"]
    assert_equal "CONSENT_REVOKED", body["reasonCode"]
  end

  def test_delegated_decision_returns_full_chain
    body = post_json("/decisions",
      { "supporterId" => "SUPPORTER-B", "scope" => "LEGAL_AID_APPLICATION",
        "at" => "2026-09-01T00:00:00Z", "record" => false })
    assert_equal "AUTHORIZED_DELEGATED_CONSENT", body["reasonCode"]
    assert_equal %w[consent delegation], body["authorityChain"].map { |l| l["type"] }
  end

  def test_replay_endpoint_matches_original
    original = post_json("/decisions",
      { "supporterId" => "SUPPORTER-B", "scope" => "LEGAL_AID_APPLICATION",
        "at" => "2026-09-01T00:00:00Z" })
    replay = post_json("/decisions/replay",
      { "supporterId" => "SUPPORTER-B", "scope" => "LEGAL_AID_APPLICATION",
        "at" => "2026-09-01T00:00:00Z", "asOfSeq" => original["asOfSeq"] })
    assert_equal original["reasonCode"], replay["reasonCode"]
    assert_equal original["authorityChain"], replay["authorityChain"]
  end

  def test_validation_error_returns_422
    post "/consents", JSON.generate({ "id" => "X" }), "CONTENT_TYPE" => "application/json"
    assert_equal 422, last_response.status
    assert JSON.parse(last_response.body)["error"]
  end

  def test_events_audit_endpoint
    get "/events"
    assert_equal 200, last_response.status
    events = JSON.parse(last_response.body)["events"]
    assert events.length >= 1
    assert(events.all? { |e| e["hash"] })
  end

  def test_recorded_decision_is_appended_to_audit
    before = (JSON.parse((get("/events"); last_response.body))["events"]).length
    post_json("/decisions",
      { "supporterId" => "SUPPORTER-A", "scope" => "LEGAL_AID_APPLICATION",
        "at" => "2026-09-01T00:00:00Z" })
    get "/events"
    after = JSON.parse(last_response.body)["events"].length
    assert_equal before + 1, after
    assert_equal "DECISION_REQUESTED", JSON.parse(last_response.body)["events"].last["type"]
  end

  def test_sub_delegation_budget_cap_over_http_returns_redacted_evidence
    # A sub-delegation whose emergency budget exceeds the source is denied, and
    # the API surfaces scope-redacted evidence — no scope leakage over the wire.
    post_json("/supporters", { "supporterId" => "SUPPORTER-BUD" })
    post_json("/consents",
      { "id" => "CONSENT-BUD", "supporterId" => "SUPPORTER-A",
        "scopes" => ["LEGAL_AID_APPLICATION"], "from" => "2026-08-01T00:00:00Z",
        "to" => "2026-12-01T00:00:00Z", "witnessId" => "W-1",
        "emergencyBudgetMinutes" => 30 })
    post_json("/delegations",
      { "id" => "DELEG-BIG", "sourceConsentId" => "CONSENT-BUD",
        "fromSupporterId" => "SUPPORTER-A", "toSupporterId" => "SUPPORTER-BUD",
        "scopes" => ["LEGAL_AID_APPLICATION"], "budgetMinutes" => 90 })
    body = post_json("/decisions",
      { "supporterId" => "SUPPORTER-BUD", "scope" => "LEGAL_AID_APPLICATION",
        "at" => "2026-09-01T00:00:00Z", "record" => false })
    assert_equal false, body["authorized"]
    assert_equal "DELEGATION_BUDGET_EXCEEDS_SOURCE", body["reasonCode"]
    refute_empty body["authorityChain"]
    body["authorityChain"].each do |link|
      refute link.key?("scopes")
      refute link.key?("scope")
      assert_equal true, link["scopesRedacted"]
    end
  end

  def test_duplicate_decision_over_http_is_idempotent
    payload = { "supporterId" => "SUPPORTER-A", "scope" => "LEGAL_AID_APPLICATION",
                "at" => "2026-09-01T00:00:00Z", "requestId" => "http-dup-1" }
    first = post_json("/decisions", payload)
    get "/events"
    count_after_first = JSON.parse(last_response.body)["events"].length

    dup = post_json("/decisions", payload)
    get "/events"
    count_after_dup = JSON.parse(last_response.body)["events"].length

    assert_equal first["reasonCode"], dup["reasonCode"]
    assert_equal first["asOfSeq"], dup["asOfSeq"]
    assert_equal first["authorityChain"], dup["authorityChain"]
    assert_equal count_after_first, count_after_dup, "resubmission must not append a second audit fact"
  end

  def test_emergency_consumption_and_revocation_over_http
    post_json("/supporters", { "supporterId" => "SUP-E" })
    post_json("/emergency-policy",
      { "allowedScope" => "LEGAL_AID_APPLICATION", "maxMinutes" => 30, "requiresReviewEvent" => false })
    post_json("/emergencies",
      { "id" => "E-HTTP", "supporterId" => "SUP-E", "scope" => "LEGAL_AID_APPLICATION",
        "at" => "2026-06-01T12:00:00Z", "maxMinutes" => 30 })
    # Consume 30 twice with the same id → still exhausted, not double counted
    # (would be no different visibly, but the second must not error/reset).
    post_json("/emergencies/E-HTTP/consumption",
      { "consumptionId" => "cc1", "minutes" => 30, "at" => "2026-06-01T12:05:00Z" })
    post_json("/emergencies/E-HTTP/consumption",
      { "consumptionId" => "cc1", "minutes" => 30, "at" => "2026-06-01T12:05:00Z" })
    exhausted = post_json("/decisions",
      { "supporterId" => "SUP-E", "scope" => "LEGAL_AID_APPLICATION",
        "at" => "2026-06-01T12:06:00Z", "record" => false })
    assert_equal "EMERGENCY_BUDGET_EXHAUSTED", exhausted["reasonCode"]

    post_json("/emergencies/E-HTTP/revocation", { "at" => "2026-06-01T12:07:00Z" })
    revoked = post_json("/decisions",
      { "supporterId" => "SUP-E", "scope" => "LEGAL_AID_APPLICATION",
        "at" => "2026-06-01T12:08:00Z", "record" => false })
    assert_equal "EMERGENCY_REVOKED", revoked["reasonCode"]
  end
end
