# frozen_string_literal: true

require "sinatra/base"
require "json"
require_relative "../consent"

module Consent
  # Thin HTTP boundary. Routes ONLY parse input, invoke the Ledger/Engine, and
  # serialize output. No authorization judgement, no time semantics, and no
  # persistence detail lives here — those belong to the pure domain and the
  # event store respectively. This keeps the security-critical logic in one
  # auditable place.
  class API < Sinatra::Base
    configure do
      set :show_exceptions, false
      set :raise_errors, false
      set :default_content_type, "application/json"
      # This is a machine-to-machine JSON API bound to loopback; the browser
      # session/CSRF protections don't apply. Disabling them keeps responses
      # clean JSON and avoids host-authorization rejections behind a proxy.
      set :protection, false
      set :host_authorization, { permitted_hosts: [] }
    end

    def self.for_ledger(ledger)
      klass = Class.new(self)
      klass.set :ledger, ledger
      klass
    end

    helpers do
      def ledger
        settings.ledger
      end

      def json_body
        raw = request.body.read
        return {} if raw.nil? || raw.empty?

        JSON.parse(raw)
      rescue JSON::ParserError => e
        halt 400, json(error: "invalid JSON: #{e.message}")
      end

      def json(obj)
        JSON.generate(obj)
      end

      def created(event)
        status 201
        json(seq: event.seq, type: event.type, hash: event.hash_value)
      end
    end

    before do
      content_type "application/json"
    end

    # --- Health -------------------------------------------------------------
    get "/health" do
      json(status: "ok", version: Consent::VERSION, events: ledger.max_seq || 0)
    end

    # --- Fact recording -----------------------------------------------------
    post "/persons" do
      b = json_body
      created(ledger.register_person(b["personId"]))
    end

    post "/supporters" do
      b = json_body
      created(ledger.add_supporter(b["supporterId"]))
    end

    post "/scopes" do
      b = json_body
      created(ledger.define_scope(b["scope"]))
    end

    post "/consents" do
      b = json_body
      created(ledger.grant_consent(
        id: b["id"], supporter_id: b["supporterId"], scopes: b["scopes"],
        from: b["from"], to: b["to"], witness_id: b["witnessId"]
      ))
    end

    post "/consents/:id/revocation" do
      b = json_body
      created(ledger.revoke_consent(consent_id: params["id"], at: b["at"]))
    end

    post "/delegations" do
      b = json_body
      created(ledger.create_delegation(
        id: b["id"], source_consent_id: b["sourceConsentId"],
        from_supporter_id: b["fromSupporterId"], to_supporter_id: b["toSupporterId"],
        scopes: b["scopes"], from: b["from"], to: b["to"]
      ))
    end

    post "/delegations/:id/revocation" do
      b = json_body
      created(ledger.revoke_delegation(delegation_id: params["id"], at: b["at"]))
    end

    post "/emergency-policy" do
      b = json_body
      created(ledger.set_emergency_policy(
        allowed_scope: b["allowedScope"], max_minutes: b["maxMinutes"],
        requires_review_event: b["requiresReviewEvent"]
      ))
    end

    post "/emergencies" do
      b = json_body
      created(ledger.invoke_emergency(
        id: b["id"], supporter_id: b["supporterId"], scope: b["scope"],
        at: b["at"], max_minutes: b["maxMinutes"]
      ))
    end

    post "/emergencies/:id/review" do
      b = json_body
      created(ledger.review_emergency(emergency_id: params["id"], at: b["at"]))
    end

    # --- Decisions ----------------------------------------------------------

    # Evaluate authority and record the decision. Pins (eventTime, asOfSeq).
    post "/decisions" do
      b = json_body
      decision = ledger.decide(
        supporter_id: b["supporterId"], scope: b["scope"], at: b["at"],
        as_of_seq: b["asOfSeq"], record: b.fetch("record", true)
      )
      status 200
      json(decision.to_h)
    end

    # Replay a decision at a fixed (eventTime, asOfSeq) without recording.
    # Same anchors must yield the identical reason code and authority chain.
    post "/decisions/replay" do
      b = json_body
      decision = ledger.evaluate(
        supporter_id: b["supporterId"], scope: b["scope"], at: b["at"],
        as_of_seq: b["asOfSeq"]
      )
      status 200
      json(decision.to_h)
    end

    # --- Audit --------------------------------------------------------------
    get "/events" do
      max = params["maxSeq"] && params["maxSeq"].to_i
      json(events: ledger.events(max_seq: max).map(&:to_h))
    end

    # --- Errors -------------------------------------------------------------
    error Consent::Ledger::ValidationError do
      status 422
      json(error: env["sinatra.error"].message)
    end

    error Consent::EventStore::TamperError do
      status 500
      json(error: "audit integrity failure: #{env['sinatra.error'].message}")
    end

    error Consent::EventStore::AppendError do
      status 409
      json(error: env["sinatra.error"].message)
    end

    error do
      status 500
      json(error: env["sinatra.error"].message)
    end

    not_found do
      json(error: "not found")
    end
  end
end
