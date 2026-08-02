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
end
