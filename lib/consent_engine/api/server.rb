require "sinatra/base"
require "json"
require "securerandom"

module ConsentEngine
  module Api
    class Server < Sinatra::Base
      configure do
        set :show_exceptions, false
        set :raise_errors, false
        set :host_authorization, { permitted_hosts: [] }
      end

      before do
        content_type :json
      end

      helpers do
        def store
          settings.store
        end

        def policy
          settings.policy
        end

        def parse_body
          body = request.body.read
          body.empty? ? {} : JSON.parse(body)
        rescue JSON::ParserError => e
          halt 400, JSON.generate({ "error" => "invalid_json", "message" => e.message })
        end

        def require_fields(data, *fields)
          missing = fields.reject { |f| data.key?(f) && !data[f].nil? }
          unless missing.empty?
            halt 422, JSON.generate({ "error" => "missing_fields", "fields" => missing })
          end
        end

        def event_to_json(event)
          JSON.generate(event.as_json)
        end

        def revoke_delegation_route
          data = parse_body
          delegation_id = params[:delegation_id]
          require_fields(data, "at")

          event = store.append(
            event_type: "DelegationRevoked",
            event_id: data["id"] || "DELEG-REVOKE-#{SecureRandom.hex(6).upcase}",
            person_id: data["personId"],
            occurred_at: data["at"],
            payload: { "delegationId" => delegation_id }
          )
          status 201
          event_to_json(event)
        end
      end

      get "/health" do
        JSON.generate({ "status" => "ok", "version" => ConsentEngine::VERSION })
      end

      get "/events" do
        events = store.all_events
        JSON.generate({ "events" => events.map(&:as_json) })
      end

      get "/events/:sequence" do
        event = store.find_event(params[:sequence].to_i)
        halt 404, JSON.generate({ "error" => "not_found" }) unless event
        event_to_json(event)
      end

      post "/people/:person_id/consents" do
        data = parse_body
        person_id = params[:person_id]
        require_fields(data, "supporterId", "scopes", "validFrom", "validTo")

        consent_id = data["id"] || "CONSENT-#{SecureRandom.hex(6).upcase}"
        occurred_at = data["occurredAt"] || data["validFrom"]

        event = store.append(
          event_type: "ConsentGranted",
          event_id: consent_id,
          person_id: person_id,
          occurred_at: occurred_at,
          payload: {
            "consentId" => consent_id,
            "supporterId" => data["supporterId"],
            "scopes" => Array(data["scopes"]),
            "validFrom" => data["validFrom"],
            "validTo" => data["validTo"],
            "witnessId" => data["witnessId"]
          }
        )
        status 201
        event_to_json(event)
      end

      post "/consents/:consent_id/revocations" do
        data = parse_body
        consent_id = params[:consent_id]
        require_fields(data, "at")

        revocation_id = data["id"] || "REVOKE-#{SecureRandom.hex(6).upcase}"
        person_id = data["personId"]

        event = store.append(
          event_type: "ConsentRevoked",
          event_id: revocation_id,
          person_id: person_id,
          occurred_at: data["at"],
          payload: {
            "revocationId" => revocation_id,
            "consentId" => consent_id
          }
        )
        status 201
        event_to_json(event)
      end

      post "/consents/:consent_id/delegations" do
        data = parse_body
        consent_id = params[:consent_id]
        require_fields(data, "toSupporterId", "scopes", "occurredAt")

        delegation_id = data["id"] || "DELEG-#{SecureRandom.hex(6).upcase}"
        person_id = data["personId"]

        event = store.append(
          event_type: "DelegationGranted",
          event_id: delegation_id,
          person_id: person_id,
          occurred_at: data["occurredAt"],
          payload: {
            "delegationId" => delegation_id,
            "sourceConsentId" => consent_id,
            "fromSupporterId" => data["fromSupporterId"],
            "toSupporterId" => data["toSupporterId"],
            "scopes" => Array(data["scopes"]),
            "validTo" => data["validTo"]
          }
        )
        status 201
        event_to_json(event)
      end

      post "/consents/delegations/:delegation_id/revocations" do
        revoke_delegation_route
      end

      post "/delegations/:delegation_id/revocations" do
        revoke_delegation_route
      end

      post "/emergencies" do
        data = parse_body
        require_fields(data, "scope", "startedAt")

        emergency_id = data["id"] || "EMERG-#{SecureRandom.hex(6).upcase}"
        event = store.append(
          event_type: "EmergencyAccessStarted",
          event_id: emergency_id,
          person_id: data["personId"],
          occurred_at: data["startedAt"],
          payload: {
            "emergencyId" => emergency_id,
            "scope" => data["scope"],
            "supporterId" => data["supporterId"]
          }
        )
        status 201
        event_to_json(event)
      end

      post "/emergencies/:emergency_id/review" do
        data = parse_body
        require_fields(data, "reviewedAt")

        event = store.append(
          event_type: "EmergencyReviewRecorded",
          event_id: data["id"] || "EMERG-REV-#{SecureRandom.hex(6).upcase}",
          person_id: data["personId"],
          occurred_at: data["reviewedAt"],
          payload: {
            "emergencyId" => params[:emergency_id]
          }
        )
        status 201
        event_to_json(event)
      end

      post "/decisions" do
        data = parse_body
        require_fields(data, "personId", "supporterId", "scope", "at")

        result = store.evaluate_decision(
          person_id: data["personId"],
          supporter_id: data["supporterId"],
          scope: data["scope"],
          at: data["at"],
          policy: policy
        )
        status 200
        JSON.generate(result.as_json)
      end

      get "/decisions/:decision_id" do
        event = store.find_decision(params[:decision_id])
        halt 404, JSON.generate({ "error" => "not_found" }) unless event
        event_to_json(event)
      end

      get "/decisions/:decision_id/verify" do
        result = store.verify_replay(params[:decision_id])
        halt 404, JSON.generate({ "error" => "not_found" }) unless result
        JSON.generate(result)
      end

      error StandardError do
        content_type :json
        status 500
        e = env["sinatra.error"]
        JSON.generate({ "error" => "internal_error", "message" => e&.message })
      end

      not_found do
        content_type :json
        status 404
        JSON.generate({ "error" => "not_found" })
      end
    end
  end
end
