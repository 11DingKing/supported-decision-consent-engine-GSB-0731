# frozen_string_literal: true

require "sinatra/base"
require "json"
require_relative "consent_engine"
require_relative "consent_engine/sqlite_event_store"

module ConsentEngine
  # Thin HTTP adapter. Routes parse JSON, call the application service, and
  # render JSON. They contain ZERO authorization rules — all judgement lives
  # in ConsentEngine::Authorizer.
  class Web < Sinatra::Base
    configure do
      set :show_exceptions, false
      set :raise_errors, false
    end

    before do
      content_type :json
    end

    helpers do
      def service
        settings.service
      end

      def parse_body!
        body = request.body.read
        return {} if body.nil? || body.empty?
        JSON.parse(body)
      rescue JSON::ParserError => e
        halt 400, JSON.generate({ error: "invalid_json", message: e.message })
      end

      def render_decision(d)
        JSON.generate(d.to_h)
      end
    end

    # ---------- health ----------
    get "/health" do
      JSON.generate({ status: "ok", high_seq: service.store.high_seq })
    end

    # ---------- persons / supporters ----------
    post "/persons" do
      p = parse_body!
      ev = service.register_person(p["personId"])
      status 201
      JSON.generate(ev.to_h)
    end

    post "/supporters" do
      p = parse_body!
      ev = service.register_supporter(p["supporterId"])
      status 201
      JSON.generate(ev.to_h)
    end

    # ---------- consent ----------
    post "/consents" do
      p = parse_body!
      ev = service.grant_consent(
        consent_id: p["id"],
        person_id: p["personId"],
        supporter_id: p["supporterId"],
        scopes: p["scopes"],
        from: p["from"],
        to: p["to"],
        witness_id: p["witnessId"],
        effective_at: p["effectiveAt"] || p["from"]
      )
      status 201
      JSON.generate(ev.to_h)
    end

    post "/revocations" do
      p = parse_body!
      ev = service.revoke_consent(
        revocation_id: p["id"],
        consent_id: p["consentId"],
        at: p["at"],
        effective_at: p["effectiveAt"] || p["at"]
      )
      status 201
      JSON.generate(ev.to_h)
    end

    # ---------- delegation ----------
    post "/delegations" do
      p = parse_body!
      ev = service.delegate(
        delegation_id: p["id"],
        source_consent_id: p["sourceConsentId"],
        from_supporter_id: p["fromSupporterId"],
        to_supporter_id: p["toSupporterId"],
        scopes: p["scopes"],
        to: p["to"],
        effective_at: p["effectiveAt"] || p["from"]
      )
      status 201
      JSON.generate(ev.to_h)
    end

    # ---------- emergency ----------
    post "/emergencies/activate" do
      p = parse_body!
      ev = service.activate_emergency(
        event_id: p["id"],
        person_id: p["personId"],
        supporter_id: p["supporterId"],
        effective_at: p["effectiveAt"]
      )
      status 201
      JSON.generate(ev.to_h)
    end

    post "/emergencies/review" do
      p = parse_body!
      ev = service.record_emergency_review(
        event_id: p["id"],
        person_id: p["personId"],
        effective_at: p["effectiveAt"]
      )
      status 201
      JSON.generate(ev.to_h)
    end

    # ---------- decisions ----------
    # Query /decide?personId=&supporterId=&scope=&as_of=
    # Every decision is:
    #   1. pinned to a high seq from the store (determinism anchor)
    #   2. evaluated by the pure domain authorizer
    #   3. itself recorded as an immutable audit event
    get "/decide" do
      person_id    = params["personId"]
      supporter_id = params["supporterId"]
      scope        = params["scope"]
      as_of        = params["asOf"]

      halt 400, JSON.generate({ error: "personId required" }) unless person_id
      halt 400, JSON.generate({ error: "scope required" })    unless scope

      d = service.decide(
        person_id: person_id,
        supporter_id: supporter_id,
        scope: scope,
        as_of: as_of
      )
      render_decision(d)
    end

    post "/decide" do
      p = parse_body!
      d = service.decide(
        person_id: p["personId"],
        supporter_id: p["supporterId"],
        scope: p["scope"],
        as_of: p["asOf"]
      )
      render_decision(d)
    end

    # Replay a prior decision using the exact (decisionAt, seenSeq) it was
    # recorded with. The reason code and chain MUST match.
    get "/decisions/:event_id/replay" do
      d = service.replay(params[:event_id])
      JSON.generate(d.to_h)
    end

    # ---------- audit ----------
    get "/events" do
      JSON.generate(service.events.map(&:to_h))
    end

    get "/events/:event_id" do
      ev = service.store.find_event(params[:event_id])
      halt 404, JSON.generate({ error: "not_found" }) unless ev
      JSON.generate(ev.to_h)
    end

    # ---------- error handling ----------
    error Service::ValidationError do
      status 400
      JSON.generate({ error: "validation_error", message: env["sinatra.error"].message })
    end

    error EventStore::DuplicateEventId, SQLiteEventStore::DuplicateEventId do
      status 409
      JSON.generate({ error: "duplicate_event", message: env["sinatra.error"].message })
    end

    error do
      status 500
      JSON.generate({ error: "internal", message: env["sinatra.error"].message })
    end
  end
end
