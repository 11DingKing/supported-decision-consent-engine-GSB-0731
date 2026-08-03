# frozen_string_literal: true

require_relative "test_helper"
require "rack/test"
require "fileutils"
require "securerandom"

ENV["RACK_ENV"] = "test"
ENV["CONSENT_DB"] = File.expand_path("../tmp/api_test_#{Process.pid}.sqlite3", __dir__)
FileUtils.rm_f([ENV["CONSENT_DB"], "#{ENV['CONSENT_DB']}-wal", "#{ENV['CONSENT_DB']}-shm"])

require_relative "../app"

# End-to-end HTTP tests. The API itself must stay thin; these tests assert
# wire behavior, stable reason codes, deterministic replay, and that the
# audit log stays immutable.
class ApiTest < Minitest::Test
  include Rack::Test::Methods

  def app = Sinatra::Application

  # Each test gets its own person/supporter ids so shared DB state is irrelevant.
  def setup
    @pid = "P-#{SecureRandom.hex(4)}"
    @sa = "SA-#{SecureRandom.hex(4)}"
    @sb = "SB-#{SecureRandom.hex(4)}"
    @sc = "SC-#{SecureRandom.hex(4)}"

    post "/persons", { personId: @pid }.to_json
    assert_equal 201, last_response.status
    [@sa, @sb, @sc].each do |s|
      post "/persons/#{@pid}/supporters", { supporterId: s }.to_json
      assert_equal 201, last_response.status
    end
    post "/persons/#{@pid}/emergency-policy",
         { allowedScope: "LEGAL_AID_APPLICATION", maxMinutes: 30, requiresReviewEvent: true }.to_json
    assert_equal 201, last_response.status
    post "/persons/#{@pid}/consents",
         { id: "C1-#{@pid}", supporterId: @sa,
           scopes: %w[LEGAL_AID_APPLICATION HOUSING_APPLICATION],
           from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z", witnessId: "W-1" }.to_json
    assert_equal 201, last_response.status
    @consent_id = "C1-#{@pid}"
  end

  def body = JSON.parse(last_response.body)

  def evaluate(supporter, scope, at)
    post "/decisions/evaluate", { personId: @pid, supporterId: supporter, scope: scope, at: at }.to_json
    assert_equal 200, last_response.status
    body
  end

  def test_direct_grant_flow_and_audit_trail
    d = evaluate(@sa, "LEGAL_AID_APPLICATION", "2026-08-10T00:00:00Z")
    assert_equal "OK_DIRECT", d["reasonCode"]
    assert d["authorized"]
    assert d["asOfSeq"] > 0

    get "/persons/#{@pid}/audit"
    types = body.map { |e| e["type"] }
    assert_includes types, "CONSENT_GRANTED"
    assert_includes types, "WITNESS_RECORDED"
    seqs = body.map { |e| e["seq"] }
    assert_equal seqs.sort, seqs
  end

  def test_silence_denied_over_http
    d = evaluate(@sb, "LEGAL_AID_APPLICATION", "2026-08-10T00:00:00Z")
    assert_equal "DENY_NO_CONSENT", d["reasonCode"]
    refute d["authorized"]
  end

  def test_consent_without_witness_rejected
    post "/persons/#{@pid}/consents",
         { supporterId: @sa, scopes: ["LEGAL_AID_APPLICATION"],
           from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z" }.to_json
    assert_equal 422, last_response.status
    assert_equal "WITNESS_REQUIRED", body["error"]
  end

  def test_delegation_and_multi_level_chain
    post "/consents/#{@consent_id}/delegations",
         { id: "D1-#{@pid}", toSupporterId: @sb, scopes: ["LEGAL_AID_APPLICATION"],
           at: "2026-08-01T00:00:00Z", to: "2026-10-01T00:00:00Z" }.to_json
    assert_equal 201, last_response.status

    post "/consents/#{@consent_id}/delegations",
         { id: "D2-#{@pid}", fromSupporterId: @sb, toSupporterId: @sc, scopes: ["LEGAL_AID_APPLICATION"],
           at: "2026-08-01T00:00:00Z", to: "2026-09-01T00:00:00Z" }.to_json
    assert_equal 201, last_response.status

    d = evaluate(@sc, "LEGAL_AID_APPLICATION", "2026-08-20T00:00:00Z")
    assert_equal "OK_DELEGATED", d["reasonCode"]
    assert_equal [@consent_id, "D1-#{@pid}", "D2-#{@pid}"], d["chain"].map { |l| l["id"] }
  end

  def test_broader_delegation_rejected_with_422
    post "/consents/#{@consent_id}/delegations",
         { toSupporterId: @sb, scopes: ["MEDICAL_INFORMATION_VIEW"], at: "2026-08-01T00:00:00Z" }.to_json
    assert_equal 422, last_response.status
    assert_equal "DELEGATION_BROADER_THAN_SOURCE", body["error"]
  end

  def test_cycle_delegation_rejected_with_422
    post "/consents/#{@consent_id}/delegations",
         { toSupporterId: @sb, scopes: ["LEGAL_AID_APPLICATION"], at: "2026-08-01T00:00:00Z" }.to_json
    assert_equal 201, last_response.status
    post "/consents/#{@consent_id}/delegations",
         { fromSupporterId: @sb, toSupporterId: @sa, scopes: ["LEGAL_AID_APPLICATION"], at: "2026-08-01T00:00:00Z" }.to_json
    assert_equal 422, last_response.status
    assert_equal "DELEGATION_CYCLE", body["error"]
  end

  def test_revoke_then_evaluate_and_double_revoke_conflict
    post "/consents/#{@consent_id}/revoke", { at: "2026-09-15T10:00:00Z" }.to_json
    assert_equal 201, last_response.status

    before = evaluate(@sa, "LEGAL_AID_APPLICATION", "2026-09-15T09:59:59Z")
    assert_equal "OK_DIRECT", before["reasonCode"]

    at_instant = evaluate(@sa, "LEGAL_AID_APPLICATION", "2026-09-15T10:00:00Z")
    assert_equal "DENY_CONSENT_REVOKED", at_instant["reasonCode"]

    post "/consents/#{@consent_id}/revoke", { at: "2026-09-16T00:00:00Z" }.to_json
    assert_equal 409, last_response.status
    assert_equal "ALREADY_REVOKED", body["error"]
  end

  def test_delegation_after_source_revocation_rejected
    post "/consents/#{@consent_id}/revoke", { at: "2026-09-15T10:00:00Z" }.to_json
    assert_equal 201, last_response.status
    post "/consents/#{@consent_id}/delegations",
         { toSupporterId: @sb, scopes: ["LEGAL_AID_APPLICATION"], at: "2026-09-16T00:00:00Z" }.to_json
    assert_equal 422, last_response.status
    assert_equal "DELEGATION_SOURCE_REVOKED", body["error"]
  end

  def test_emergency_flow_with_review_and_timeout
    post "/persons/#{@pid}/emergencies",
         { id: "E1-#{@pid}", supporterId: @sb, scope: "LEGAL_AID_APPLICATION", at: "2026-08-10T10:00:00Z" }.to_json
    assert_equal 201, last_response.status

    pending = evaluate(@sb, "LEGAL_AID_APPLICATION", "2026-08-10T10:15:00Z")
    assert_equal "OK_EMERGENCY_REVIEW_PENDING", pending["reasonCode"]
    assert pending["authorized"]

    post "/emergencies/E1-#{@pid}/review", { reviewerId: "SW-1", at: "2026-08-10T10:20:00Z" }.to_json
    assert_equal 201, last_response.status

    reviewed = evaluate(@sb, "LEGAL_AID_APPLICATION", "2026-08-10T10:15:00Z")
    assert_equal "OK_EMERGENCY", reviewed["reasonCode"]

    timeout = evaluate(@sb, "LEGAL_AID_APPLICATION", "2026-08-10T10:31:00Z")
    assert_equal "DENY_EMERGENCY_TIMEOUT", timeout["reasonCode"]
    refute timeout["authorized"]
  end

  def test_emergency_scope_outside_policy_rejected
    post "/persons/#{@pid}/emergencies",
         { supporterId: @sb, scope: "MEDICAL_INFORMATION_VIEW", at: "2026-08-10T10:00:00Z" }.to_json
    assert_equal 422, last_response.status
    assert_equal "EMERGENCY_SCOPE_NOT_ALLOWED", body["error"]
  end

  # Determinism: a decision pinned to (event time, as-of seq) replays to the
  # identical verdict even after many later facts are appended.
  def test_replay_is_stable_after_history_grows
    d = evaluate(@sa, "LEGAL_AID_APPLICATION", "2026-08-10T00:00:00Z")

    post "/consents/#{@consent_id}/revoke", { at: "2026-09-15T10:00:00Z" }.to_json
    post "/persons/#{@pid}/consents",
         { supporterId: @sb, scopes: ["HOUSING_APPLICATION"],
           from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z", witnessId: "W-2" }.to_json

    get "/decisions/#{d['decisionId']}/replay"
    assert_equal 200, last_response.status
    assert body["replayMatches"]
    assert_equal "OK_DIRECT", body["replay"]["reasonCode"]
    assert_equal body["chain"], body["replay"]["chain"]
  end

  def test_unknown_decision_replay_404
    get "/decisions/DEC-nope/replay"
    assert_equal 404, last_response.status
  end

  # --- round 2: sub-delegation evidence, budgets, late arrival ----------------

  def audit_events(type)
    get "/persons/#{@pid}/audit"
    body.select { |e| e["type"] == type }
  end

  def test_rejected_subdelegation_leaves_scope_redacted_evidence
    post "/consents/#{@consent_id}/delegations",
         { toSupporterId: @sb, scopes: ["MEDICAL_INFORMATION_VIEW"], at: "2026-08-01T00:00:00Z" }.to_json
    assert_equal 422, last_response.status
    assert_equal "DELEGATION_BROADER_THAN_SOURCE", body["error"]
    assert body["rejectionId"], "rejection must carry an evidence id"
    rejection_id = body["rejectionId"]

    rejected = audit_events("DELEGATION_REJECTED")
    assert_equal 1, rejected.size
    payload = rejected.first["payload"]
    assert_equal "DELEGATION_BROADER_THAN_SOURCE", payload["reasonCode"]
    assert_equal rejection_id, payload["id"]
    assert_equal "rejected", payload["chain"].last["status"]

    # Evidence must not disclose any scope contents — not the requested one
    # and not the source's.
    json = payload["chain"].to_json
    refute_includes json, "MEDICAL_INFORMATION_VIEW"
    refute_includes json, "LEGAL_AID_APPLICATION"
    refute_includes json, "HOUSING_APPLICATION"
    assert_equal 0, audit_events("DELEGATION_CREATED").size
  end

  def test_cumulative_budget_over_allocation_over_http
    post "/consents/#{@consent_id}/delegations",
         { toSupporterId: @sb, scopes: ["LEGAL_AID_APPLICATION"],
           at: "2026-08-01T00:00:00Z", emergencyBudgetMinutes: 20 }.to_json
    assert_equal 201, last_response.status

    post "/consents/#{@consent_id}/delegations",
         { toSupporterId: @sc, scopes: ["LEGAL_AID_APPLICATION"],
           at: "2026-08-01T00:00:00Z", emergencyBudgetMinutes: 20 }.to_json
    assert_equal 422, last_response.status
    assert_equal "DELEGATION_BUDGET_EXCEEDED", body["error"]

    post "/consents/#{@consent_id}/delegations",
         { toSupporterId: @sc, scopes: ["LEGAL_AID_APPLICATION"],
           at: "2026-08-01T00:00:00Z", emergencyBudgetMinutes: 10 }.to_json
    assert_equal 201, last_response.status
  end

  def test_consent_budget_above_person_policy_rejected
    post "/persons/#{@pid}/consents",
         { supporterId: @sb, scopes: ["HOUSING_APPLICATION"],
           from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z",
           witnessId: "W-2", emergencyBudgetMinutes: 45 }.to_json
    assert_equal 422, last_response.status
    assert_equal "CONSENT_BUDGET_EXCEEDS_POLICY", body["error"]
  end

  def test_late_arriving_subchain_validity_by_event_time_and_seq_over_http
    post "/consents/#{@consent_id}/revoke", { at: "2026-09-15T10:00:00Z" }.to_json
    assert_equal 201, last_response.status

    early = evaluate(@sb, "LEGAL_AID_APPLICATION", "2026-09-14T12:00:00Z")
    assert_equal "DENY_NO_CONSENT", early["reasonCode"]

    # Arrives after the revocation in audit order, effective before it.
    post "/consents/#{@consent_id}/delegations",
         { toSupporterId: @sb, scopes: ["LEGAL_AID_APPLICATION"],
           at: "2026-09-14T00:00:00Z", emergencyBudgetMinutes: 10 }.to_json
    assert_equal 201, last_response.status

    now = evaluate(@sb, "LEGAL_AID_APPLICATION", "2026-09-14T12:00:00Z")
    assert_equal "OK_DELEGATED", now["reasonCode"]

    post_revoke = evaluate(@sb, "LEGAL_AID_APPLICATION", "2026-09-15T11:00:00Z")
    assert_equal "DENY_DELEGATION_SOURCE_REVOKED", post_revoke["reasonCode"]

    get "/decisions/#{early['decisionId']}/replay"
    assert body["replayMatches"]
    assert_equal "DENY_NO_CONSENT", body["replay"]["reasonCode"]
  end
end
