# frozen_string_literal: true

require "json"
require "securerandom"
require "sinatra"
require "time"

require_relative "lib/domain"
require_relative "lib/store"

# Thin HTTP layer. Routes parse/serialize JSON and orchestrate calls into the
# pure domain layer (Domain::Validate, Domain::Authorizer via Store). No
# authorization rule lives here or in the persistence layer.

set :environment, ENV.fetch("RACK_ENV", "development").to_sym
set :host_authorization, { permitted_hosts: [] }
set :default_content_type, :json

DB_PATH = ENV.fetch("CONSENT_DB", File.join(__dir__, "db", "consent.sqlite3"))
require "fileutils"
FileUtils.mkdir_p(File.dirname(DB_PATH))
STORE = Store.new(DB_PATH)
STORE_MUTEX = Mutex.new

helpers do
  def json_body
    request.body.rewind
    JSON.parse(request.body.read)
  rescue JSON::ParserError
    halt 400, { error: "BAD_JSON" }.to_json
  end

  def parse_time(value, field)
    halt 400, { error: "TIME_MISSING", field: field }.to_json if value.nil?
    Time.iso8601(value.to_s)
  rescue ArgumentError
    halt 400, { error: "TIME_INVALID", field: field }.to_json
  end

  def now_utc = Time.now.utc

  def domain_error(code)
    status = %w[ALREADY_REVOKED].include?(code) ? 409 : 422
    halt status, { error: code }.to_json
  end

  def synchronized(&block) = STORE_MUTEX.synchronize(&block)
end

before { content_type :json }

get "/health" do
  { status: "ok" }.to_json
end

post "/persons" do
  body = json_body
  halt 400, { error: "PERSON_ID_REQUIRED" }.to_json if body["personId"].to_s.empty?
  seq = synchronized do
    STORE.in_transaction { STORE.append_event(type: "PERSON_REGISTERED", payload: { "personId" => body["personId"] }, event_time: now_utc) }
  end
  status 201
  { personId: body["personId"], seq: seq }.to_json
end

post "/persons/:person_id/supporters" do
  body = json_body
  halt 400, { error: "SUPPORTER_ID_REQUIRED" }.to_json if body["supporterId"].to_s.empty?
  seq = synchronized do
    STORE.in_transaction do |s|
      domain_error("PERSON_UNKNOWN") unless STORE.world(as_of_seq: s).persons.include?(params[:person_id])
      STORE.append_event(type: "SUPPORTER_REGISTERED",
                         payload: { "personId" => params[:person_id], "supporterId" => body["supporterId"] },
                         event_time: now_utc)
    end
  end
  status 201
  { supporterId: body["supporterId"], seq: seq }.to_json
end

post "/persons/:person_id/emergency-policy" do
  body = json_body
  seq = synchronized do
    STORE.in_transaction do
      STORE.append_event(type: "EMERGENCY_POLICY_SET",
                         payload: { "personId" => params[:person_id],
                                    "allowedScope" => body["allowedScope"],
                                    "maxMinutes" => body["maxMinutes"],
                                    "requiresReviewEvent" => body["requiresReviewEvent"] },
                         event_time: now_utc)
    end
  end
  status 201
  { seq: seq }.to_json
end

post "/persons/:person_id/consents" do
  body = json_body
  valid_from = parse_time(body["from"], "from")
  valid_to = parse_time(body["to"], "to")
  id = body["id"] || "CONSENT-#{SecureRandom.uuid}"
  seq = synchronized do
    STORE.in_transaction do |s|
      err = Domain::Validate.consent(world: STORE.world(as_of_seq: s), person_id: params[:person_id],
                                     supporter_id: body["supporterId"], scopes: body["scopes"],
                                     valid_from: valid_from, valid_to: valid_to, witness_id: body["witnessId"],
                                     emergency_budget_minutes: body["emergencyBudgetMinutes"])
      domain_error(err) if err
      STORE.append_event(type: "CONSENT_GRANTED",
                         payload: { "id" => id, "personId" => params[:person_id],
                                    "supporterId" => body["supporterId"], "scopes" => body["scopes"],
                                    "from" => valid_from.utc.iso8601, "to" => valid_to.utc.iso8601,
                                    "witnessId" => body["witnessId"],
                                    "emergencyBudgetMinutes" => body["emergencyBudgetMinutes"] },
                         event_time: valid_from)
      STORE.append_event(type: "WITNESS_RECORDED",
                         payload: { "consentId" => id, "witnessId" => body["witnessId"],
                                    "personId" => params[:person_id] },
                         event_time: valid_from)
    end
  end
  status 201
  { consentId: id, seq: seq }.to_json
end

post "/consents/:consent_id/revoke" do
  body = json_body
  at = body["at"] ? parse_time(body["at"], "at") : now_utc
  id = body["id"] || "REVOKE-#{SecureRandom.uuid}"
  seq = synchronized do
    STORE.in_transaction do |s|
      err = Domain::Validate.revocation(world: STORE.world(as_of_seq: s), consent_id: params[:consent_id])
      domain_error(err) if err
      STORE.append_event(type: "CONSENT_REVOKED",
                         payload: { "id" => id, "consentId" => params[:consent_id], "at" => at.utc.iso8601 },
                         event_time: at)
    end
  end
  status 201
  { revocationId: id, consentId: params[:consent_id], at: at.utc.iso8601, seq: seq }.to_json
end

post "/consents/:consent_id/delegations" do
  body = json_body
  effective_from = body["at"] ? parse_time(body["at"], "at") : now_utc
  valid_to = body["to"] && parse_time(body["to"], "to")
  id = body["id"] || "DELEG-#{SecureRandom.uuid}"
  err = nil
  rejection_id = nil
  seq = synchronized do
    STORE.in_transaction do |s|
      world = STORE.world(as_of_seq: s)
      root = world.consent_by_id(params[:consent_id])
      if root.nil?
        err = "SOURCE_CONSENT_UNKNOWN"
        next s
      end
      from_supporter = body["fromSupporterId"] || root.supporter_id
      err = Domain::Validate.delegation(world: world, source_consent_id: params[:consent_id],
                                        from_supporter_id: from_supporter,
                                        to_supporter_id: body["toSupporterId"],
                                        scopes: body["scopes"],
                                        effective_from: effective_from, valid_to: valid_to,
                                        emergency_budget_minutes: body["emergencyBudgetMinutes"])
      if err
        # Rejected sub-chains leave immutable, scope-redacted evidence: the
        # stable reason code and the chain that justified the refusal.
        rejection_id = "REJ-#{SecureRandom.uuid}"
        evidence = Domain::Evidence.delegation_rejection(world: world, source_consent_id: params[:consent_id],
                                                         from_supporter_id: from_supporter,
                                                         to_supporter_id: body["toSupporterId"],
                                                         attempted_id: id, at: effective_from, reason: err)
        STORE.append_event(type: "DELEGATION_REJECTED",
                           payload: { "id" => rejection_id, "attemptedDelegationId" => id,
                                      "sourceConsentId" => params[:consent_id],
                                      "fromSupporterId" => from_supporter,
                                      "toSupporterId" => body["toSupporterId"],
                                      "reasonCode" => err, "chain" => evidence },
                           event_time: effective_from)
      else
        STORE.append_event(type: "DELEGATION_CREATED",
                           payload: { "id" => id, "sourceConsentId" => params[:consent_id],
                                      "fromSupporterId" => from_supporter,
                                      "toSupporterId" => body["toSupporterId"],
                                      "scopes" => body["scopes"],
                                      "effectiveFrom" => effective_from.utc.iso8601,
                                      "to" => valid_to&.utc&.iso8601,
                                      "emergencyBudgetMinutes" => body["emergencyBudgetMinutes"] },
                           event_time: effective_from)
      end
      s
    end
  end
  halt 422, { error: err, rejectionId: rejection_id }.to_json if err
  status 201
  { delegationId: id, seq: seq }.to_json
end

post "/persons/:person_id/emergencies" do
  body = json_body
  at = body["at"] ? parse_time(body["at"], "at") : now_utc
  id = body["id"] || "EMG-#{SecureRandom.uuid}"
  seq = synchronized do
    STORE.in_transaction do |s|
      world = STORE.world(as_of_seq: s)
      err = Domain::Validate.emergency_start(world: world, person_id: params[:person_id],
                                             supporter_id: body["supporterId"], scope: body["scope"])
      domain_error(err) if err
      policy = world.emergency_policies[params[:person_id]]
      STORE.append_event(type: "EMERGENCY_STARTED",
                         payload: { "id" => id, "personId" => params[:person_id],
                                    "supporterId" => body["supporterId"], "scope" => body["scope"],
                                    "startedAt" => at.utc.iso8601, "maxMinutes" => policy.max_minutes },
                         event_time: at)
    end
  end
  status 201
  { emergencyId: id, seq: seq }.to_json
end

post "/emergencies/:emergency_id/review" do
  body = json_body
  at = body["at"] ? parse_time(body["at"], "at") : now_utc
  seq = synchronized do
    STORE.in_transaction do
      STORE.append_event(type: "EMERGENCY_REVIEWED",
                         payload: { "emergencyId" => params[:emergency_id],
                                    "reviewerId" => body["reviewerId"], "at" => at.utc.iso8601 },
                         event_time: at)
    end
  end
  status 201
  { emergencyId: params[:emergency_id], seq: seq }.to_json
end

# The decision endpoint pins both the event time and the audit sequence it
# observed; the verdict is journaled and can be replayed deterministically.
post "/decisions/evaluate" do
  body = json_body
  at = parse_time(body["at"], "at")
  halt 400, { error: "SCOPE_REQUIRED" }.to_json if body["scope"].to_s.empty?
  result = synchronized do
    STORE.evaluate_and_record(person_id: body["personId"], supporter_id: body["supporterId"],
                              scope: body["scope"], at: at)
  end
  status 200
  result.to_json
end

get "/decisions/:id" do
  decision = synchronized { STORE.fetch_decision(params[:id]) }
  halt 404, { error: "DECISION_UNKNOWN" }.to_json if decision.nil?
  decision.to_json
end

get "/decisions/:id/replay" do
  result = synchronized { STORE.replay_decision(params[:id]) }
  halt 404, { error: "DECISION_UNKNOWN" }.to_json if result.nil?
  result.to_json
end

get "/persons/:person_id/audit" do
  synchronized { STORE.audit_trail(params[:person_id]) }.to_json
end

# Seed the blank database from the authoritative source material. Invalid
# facts (e.g. a delegation broader than its source) are validated by the
# domain layer and refused, exactly as they would be over the API.
def seed_from_materials!
  return if STORE.max_seq.positive?

  path = File.join(__dir__, "materials", "consent-cases.json")
  return unless File.exist?(path)

  m = JSON.parse(File.read(path))
  STORE.in_transaction do
    STORE.append_event(type: "PERSON_REGISTERED", payload: { "personId" => m["personId"] }, event_time: Time.now.utc)
    m["supporters"].each do |s|
      STORE.append_event(type: "SUPPORTER_REGISTERED", payload: { "personId" => m["personId"], "supporterId" => s }, event_time: Time.now.utc)
    end
    em = m["emergency"]
    STORE.append_event(type: "EMERGENCY_POLICY_SET",
                       payload: { "personId" => m["personId"], "allowedScope" => em["allowedScope"],
                                  "maxMinutes" => em["maxMinutes"], "requiresReviewEvent" => em["requiresReviewEvent"] },
                       event_time: Time.now.utc)
    m["consents"].each do |c|
      STORE.append_event(type: "CONSENT_GRANTED",
                         payload: { "id" => c["id"], "personId" => m["personId"], "supporterId" => c["supporterId"],
                                    "scopes" => c["scopes"], "from" => c["from"], "to" => c["to"],
                                    "witnessId" => c["witnessId"] },
                         event_time: Time.iso8601(c["from"]))
      STORE.append_event(type: "WITNESS_RECORDED",
                         payload: { "consentId" => c["id"], "witnessId" => c["witnessId"], "personId" => m["personId"] },
                         event_time: Time.iso8601(c["from"]))
    end
    world = STORE.world
    m["delegations"].each do |d|
      root = world.consent_by_id(d["sourceConsentId"])
      effective_from = root.valid_from
      err = Domain::Validate.delegation(world: world, source_consent_id: d["sourceConsentId"],
                                        from_supporter_id: d["fromSupporterId"], to_supporter_id: d["toSupporterId"],
                                        scopes: d["scopes"], effective_from: effective_from,
                                        valid_to: d["to"] && Time.iso8601(d["to"]))
      if err
        warn "seed: delegation #{d['id']} refused by domain validation: #{err}"
        next
      end
      STORE.append_event(type: "DELEGATION_CREATED",
                         payload: { "id" => d["id"], "sourceConsentId" => d["sourceConsentId"],
                                    "fromSupporterId" => d["fromSupporterId"], "toSupporterId" => d["toSupporterId"],
                                    "scopes" => d["scopes"], "effectiveFrom" => effective_from.utc.iso8601,
                                    "to" => d["to"] },
                         event_time: effective_from)
    end
    m["revocations"].each do |r|
      STORE.append_event(type: "CONSENT_REVOKED",
                         payload: { "id" => r["id"], "consentId" => r["consentId"], "at" => r["at"] },
                         event_time: Time.iso8601(r["at"]))
    end
  end
  warn "seed: loaded materials/consent-cases.json (#{STORE.max_seq} events)"
end

seed_from_materials! unless settings.environment == :test

Sinatra::Application.run! if __FILE__ == $PROGRAM_NAME
