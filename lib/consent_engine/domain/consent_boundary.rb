module ConsentEngine
  module Domain
    class ConsentBoundary
      attr_reader :events, :request, :policy

      def initialize(events, request, policy)
        @events = events.sort_by(&:sequence).freeze
        @request = request
        @policy = policy
      end

      def self.evaluate(events, request, policy)
        new(events, request, policy).evaluate
      end

      def evaluate
        seen = events.map(&:sequence).max || 0
        state = replay(events)

        result = evaluate_ordinary(state, seen)
        return result if result.authorized?

        emergency = evaluate_emergency(state, seen)
        return emergency if emergency

        result
      end

      private

      def pt(value)
        return nil if value.nil?
        return value if value.is_a?(Time)
        Time.iso8601(value.to_s).utc
      end

      def replay(evts)
        state = {
          consents: {},
          delegations: {},
          emergencies: [],
          decisions: []
        }
        evts.each do |e|
          case e.type
          when "ConsentGranted"
            state[:consents][e.payload["consentId"]] = {
              consent_id: e.payload["consentId"],
              person_id: e.person_id,
              supporter_id: e.payload["supporterId"],
              scopes: ScopeSet.new(e.payload["scopes"]),
              valid_from: pt(e.payload["validFrom"]),
              valid_to: pt(e.payload["validTo"]),
              witness_id: e.payload["witnessId"],
              granted_at: e.occurred_at,
              revoked_at: nil
            }
          when "ConsentRevoked"
            cid = e.payload["consentId"]
            state[:consents][cid]&.[]=(:revoked_at, e.occurred_at)
          when "DelegationGranted"
            state[:delegations][e.payload["delegationId"]] = {
              delegation_id: e.payload["delegationId"],
              source_consent_id: e.payload["sourceConsentId"],
              from_supporter_id: e.payload["fromSupporterId"],
              to_supporter_id: e.payload["toSupporterId"],
              scopes: ScopeSet.new(e.payload["scopes"]),
              valid_to: pt(e.payload["validTo"]),
              granted_at: e.occurred_at,
              revoked_at: nil
            }
          when "DelegationRevoked"
            did = e.payload["delegationId"]
            state[:delegations][did]&.[]=(:revoked_at, e.occurred_at)
          when "EmergencyAccessStarted"
            state[:emergencies] << {
              emergency_id: e.payload["emergencyId"],
              scope: e.payload["scope"],
              supporter_id: e.payload["supporterId"],
              started_at: e.occurred_at,
              reviewed_at: nil
            }
          when "EmergencyReviewRecorded"
            eid = e.payload["emergencyId"]
            em = state[:emergencies].find { |x| x[:emergency_id] == eid }
            em&.[]=(:reviewed_at, e.occurred_at)
          when "DecisionRecorded"
            state[:decisions] << e.payload
          end
        end
        state
      end

      def evaluate_ordinary(state, seen)
        t = request[:at]
        supporter = request[:supporter_id]
        scope = request[:scope]
        person = request[:person_id]
        reasons = []

        direct = state[:consents].values.select do |c|
          c[:supporter_id] == supporter && c[:person_id] == person
        end

        direct.each do |c|
          reason = check_consent(c, scope, t)
          if reason.nil?
            link = build_consent_link(c, t)
            return DecisionResult.new(
              person_id: person, supporter_id: supporter, scope: scope,
              decision_at: t, seen_sequence: seen,
              reason_code: ReasonCode::AUTHORIZED, chain: [link]
            )
          else
            reasons << reason
          end
        end

        delegs = state[:delegations].values.select do |d|
          d[:to_supporter_id] == supporter
        end

        delegs.each do |d|
          chain, reason = walk_delegation(d, state, scope, t, [supporter])
          if chain
            return DecisionResult.new(
              person_id: person, supporter_id: supporter, scope: scope,
              decision_at: t, seen_sequence: seen,
              reason_code: ReasonCode::AUTHORIZED, chain: chain
            )
          else
            reasons << reason if reason
          end
        end

        reasons << ReasonCode::NO_CONSENT if reasons.empty?
        code = ReasonCode.strongest(reasons)
        DecisionResult.new(
          person_id: person, supporter_id: supporter, scope: scope,
          decision_at: t, seen_sequence: seen, reason_code: code, chain: []
        )
      end

      def check_consent(c, scope, t)
        return ReasonCode::WITNESS_MISSING if c[:witness_id].nil? || c[:witness_id].to_s.empty?
        return ReasonCode::SCOPE_NOT_GRANTED unless c[:scopes].include?(scope)

        window = TimeWindow.new(c[:valid_from], c[:valid_to])
        return ReasonCode::NOT_YET_VALID if window.before_start?(t)
        return ReasonCode::EXPIRED if window.ended?(t)

        if c[:revoked_at] && t >= c[:revoked_at]
          return ReasonCode::REVOKED
        end

        nil
      end

      def walk_delegation(d, state, scope, t, visited)
        source = state[:consents][d[:source_consent_id]]

        return [nil, ReasonCode::DELEGATION_WITHOUT_SOURCE] unless source

        if visited.include?(d[:from_supporter_id])
          return [nil, ReasonCode::DELEGATION_CYCLE]
        end

        unless d[:scopes].include?(scope)
          return [nil, ReasonCode::SCOPE_NOT_GRANTED]
        end

        unless d[:scopes].subset_of?(source[:scopes])
          return [nil, ReasonCode::DELEGATION_BROADER_THAN_SOURCE]
        end

        source_window = TimeWindow.new(source[:valid_from], source[:valid_to])
        if source[:revoked_at] && d[:granted_at] >= source[:revoked_at]
          return [nil, ReasonCode::DELEGATION_SOURCE_REVOKED]
        end
        if source_window.ended?(d[:granted_at])
          return [nil, ReasonCode::DELEGATION_SOURCE_EXPIRED]
        end
        if source_window.before_start?(d[:granted_at])
          return [nil, ReasonCode::DELEGATION_SOURCE_NOT_YET_VALID]
        end

        if d[:valid_to] && t >= d[:valid_to]
          return [nil, ReasonCode::DELEGATION_EXPIRED]
        end
        if t < d[:granted_at]
          return [nil, ReasonCode::DELEGATION_NOT_YET_VALID]
        end
        if d[:revoked_at] && t >= d[:revoked_at]
          return [nil, ReasonCode::REVOKED]
        end

        if source[:revoked_at] && t >= source[:revoked_at]
          return [nil, ReasonCode::DELEGATION_SOURCE_REVOKED]
        end
        if source_window.before_start?(t)
          return [nil, ReasonCode::DELEGATION_SOURCE_NOT_YET_VALID]
        end
        if source_window.ended?(t)
          return [nil, ReasonCode::DELEGATION_SOURCE_EXPIRED]
        end
        if source[:witness_id].nil? || source[:witness_id].to_s.empty?
          return [nil, ReasonCode::WITNESS_MISSING]
        end

        sub_chain, sub_reason = find_authorization_chain(
          state, d[:from_supporter_id], source[:person_id], scope, t,
          visited + [d[:from_supporter_id]]
        )

        return [nil, sub_reason || ReasonCode::NO_CONSENT] unless sub_chain

        link = build_delegation_link(d, source, t)
        [sub_chain + [link], nil]
      end

      def find_authorization_chain(state, supporter, person, scope, t, visited)
        direct = state[:consents].values.find do |c|
          c[:supporter_id] == supporter &&
            c[:person_id] == person &&
            check_consent(c, scope, t).nil?
        end
        return [[build_consent_link(direct, t)], nil] if direct

        delegs = state[:delegations].values.select do |d|
          d[:to_supporter_id] == supporter
        end

        reasons = []
        delegs.each do |d|
          chain, reason = walk_delegation(d, state, scope, t, visited)
          return [chain, nil] if chain
          reasons << reason if reason
        end
        [nil, ReasonCode.strongest(reasons)]
      end

      def evaluate_emergency(state, seen)
        t = request[:at]
        scope = request[:scope]
        supporter = request[:supporter_id]

        return nil unless policy && policy.allowed_scope
        return nil unless scope == policy.allowed_scope

        candidate = state[:emergencies]
          .select { |e| e[:scope] == scope && e[:started_at] <= t }
          .min_by { |e| e[:started_at] }

        return nil unless candidate

        deadline = candidate[:started_at] + (policy.max_minutes * 60)
        within_window = t < deadline

        if within_window
          DecisionResult.new(
            person_id: request[:person_id], supporter_id: supporter,
            scope: scope, decision_at: t, seen_sequence: seen,
            reason_code: ReasonCode::EMERGENCY_AUTHORIZED, chain: [],
            emergency: {
              "emergencyId" => candidate[:emergency_id],
              "startedAt" => candidate[:started_at].iso8601,
              "deadlineAt" => deadline.iso8601,
              "reviewRecorded" => !candidate[:reviewed_at].nil?,
              "reviewRequired" => policy.requires_review_event
            }
          )
        else
          DecisionResult.new(
            person_id: request[:person_id], supporter_id: supporter,
            scope: scope, decision_at: t, seen_sequence: seen,
            reason_code: ReasonCode::EMERGENCY_TIMEOUT, chain: [],
            emergency: {
              "emergencyId" => candidate[:emergency_id],
              "startedAt" => candidate[:started_at].iso8601,
              "deadlineAt" => deadline.iso8601,
              "expiredAt" => deadline.iso8601,
              "reviewRecorded" => !candidate[:reviewed_at].nil?
            }
          )
        end
      end

      def build_consent_link(c, t)
        window = TimeWindow.new(c[:valid_from], c[:valid_to])
        status = if c[:revoked_at] && t >= c[:revoked_at]
                   "REVOKED"
                 elsif window.ended?(t)
                   "EXPIRED"
                 elsif window.before_start?(t)
                   "NOT_YET_VALID"
                 else
                   "ACTIVE"
                 end
        ChainLink.new(
          kind: :consent,
          id: c[:consent_id],
          from_subject: c[:person_id],
          to_supporter_id: c[:supporter_id],
          scopes: c[:scopes],
          window: window,
          witness_id: c[:witness_id],
          occurred_at: c[:granted_at],
          status: status
        )
      end

      def build_delegation_link(d, source, t)
        status = if d[:revoked_at] && t >= d[:revoked_at]
                   "REVOKED"
                 elsif d[:valid_to] && t >= d[:valid_to]
                   "EXPIRED"
                 else
                   "ACTIVE"
                 end
        ChainLink.new(
          kind: :delegation,
          id: d[:delegation_id],
          from_subject: d[:from_supporter_id],
          to_supporter_id: d[:to_supporter_id],
          scopes: d[:scopes],
          window: TimeWindow.new(d[:granted_at], d[:valid_to]),
          source_consent_id: source[:consent_id],
          occurred_at: d[:granted_at],
          status: status
        )
      end
    end
  end
end
