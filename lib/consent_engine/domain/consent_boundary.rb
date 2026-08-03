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
        t = request[:at]
        seen = events.map(&:sequence).max || 0
        visible = events.select { |e| e.occurred_at <= t }
        state = replay(visible)

        result = evaluate_ordinary(state, seen, t)
        return result if result.authorized?

        emergency = evaluate_emergency(state, seen, t)
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
              sequence: e.sequence,
              revoked_at: nil,
              revoked_sequence: nil
            }
          when "ConsentRevoked"
            cid = e.payload["consentId"]
            c = state[:consents][cid]
            if c
              if c[:revoked_at].nil? || e.occurred_at < c[:revoked_at]
                c[:revoked_at] = e.occurred_at
                c[:revoked_sequence] = e.sequence
              end
            end
          when "DelegationGranted"
            state[:delegations][e.payload["delegationId"]] = {
              delegation_id: e.payload["delegationId"],
              source_consent_id: e.payload["sourceConsentId"],
              from_supporter_id: e.payload["fromSupporterId"],
              to_supporter_id: e.payload["toSupporterId"],
              scopes: ScopeSet.new(e.payload["scopes"]),
              valid_to: pt(e.payload["validTo"]),
              emergency_budget_minutes: e.payload["emergencyBudgetMinutes"],
              granted_at: e.occurred_at,
              sequence: e.sequence,
              revoked_at: nil,
              revoked_sequence: nil
            }
          when "DelegationRevoked"
            did = e.payload["delegationId"]
            d = state[:delegations][did]
            if d
              if d[:revoked_at].nil? || e.occurred_at < d[:revoked_at]
                d[:revoked_at] = e.occurred_at
                d[:revoked_sequence] = e.sequence
              end
            end
          when "EmergencyAccessStarted"
            state[:emergencies] << {
              emergency_id: e.payload["emergencyId"],
              scope: e.payload["scope"],
              supporter_id: e.payload["supporterId"],
              source_consent_id: e.payload["sourceConsentId"],
              started_at: e.occurred_at,
              sequence: e.sequence,
              consumed_minutes: e.payload["consumedMinutes"],
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

      def evaluate_ordinary(state, seen, t)
        supporter = request[:supporter_id]
        scope = request[:scope]
        person = request[:person_id]
        reasons = []
        best_evidence = []

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
          chain, reason, evidence = walk_delegation(d, state, scope, t, [supporter])
          if chain
            return DecisionResult.new(
              person_id: person, supporter_id: supporter, scope: scope,
              decision_at: t, seen_sequence: seen,
              reason_code: ReasonCode::AUTHORIZED, chain: chain
            )
          else
            reasons << reason if reason
            if reason && evidence && !evidence.empty?
              prio = ReasonCode::DENIAL_PRIORITY.fetch(reason, -1)
              best_prio = best_evidence.empty? ? -1 :
                ReasonCode::DENIAL_PRIORITY.fetch(best_evidence.first, -1)
              if best_evidence.empty? || prio > best_prio
                best_evidence = [reason, evidence]
              end
            end
          end
        end

        reasons << ReasonCode::NO_CONSENT if reasons.empty?
        code = ReasonCode.strongest(reasons)
        evidence_chain = best_evidence.empty? ? [] : best_evidence.last
        DecisionResult.new(
          person_id: person, supporter_id: supporter, scope: scope,
          decision_at: t, seen_sequence: seen, reason_code: code,
          chain: evidence_chain
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

        unless source
          evidence = [build_delegation_link(d, nil, t, redacted: true)]
          return [nil, ReasonCode::DELEGATION_WITHOUT_SOURCE, evidence]
        end

        source_link = build_consent_link(source, t, redacted: true)
        deleg_link = build_delegation_link(d, source, t, redacted: true)
        base_evidence = [source_link, deleg_link]

        if visited.include?(d[:from_supporter_id])
          return [nil, ReasonCode::DELEGATION_CYCLE, base_evidence]
        end

        unless d[:scopes].include?(scope)
          return [nil, ReasonCode::SCOPE_NOT_GRANTED, base_evidence]
        end

        unless d[:scopes].subset_of?(source[:scopes])
          return [nil, ReasonCode::DELEGATION_BROADER_THAN_SOURCE, base_evidence]
        end

        source_window = TimeWindow.new(source[:valid_from], source[:valid_to])

        if source[:revoked_at]
          if d[:granted_at] >= source[:revoked_at]
            return [nil, ReasonCode::DELEGATION_SOURCE_REVOKED, base_evidence]
          end
          if d[:sequence] && source[:revoked_sequence] &&
             d[:sequence] > source[:revoked_sequence]
            return [nil, ReasonCode::DELEGATION_LATE_ARRIVAL, base_evidence]
          end
        end

        if source_window.ended?(d[:granted_at])
          return [nil, ReasonCode::DELEGATION_SOURCE_EXPIRED, base_evidence]
        end
        if source_window.before_start?(d[:granted_at])
          return [nil, ReasonCode::DELEGATION_SOURCE_NOT_YET_VALID, base_evidence]
        end

        if d[:valid_to] && source[:valid_to] && d[:valid_to] > source[:valid_to]
          return [nil, ReasonCode::DELEGATION_DURATION_EXCEEDS_SOURCE, base_evidence]
        end

        budget_reason = check_budget(d, source, state, t)
        if budget_reason
          return [nil, budget_reason, base_evidence]
        end

        if d[:valid_to] && t >= d[:valid_to]
          return [nil, ReasonCode::DELEGATION_EXPIRED, base_evidence]
        end
        if t < d[:granted_at]
          return [nil, ReasonCode::DELEGATION_NOT_YET_VALID, base_evidence]
        end
        if d[:revoked_at] && t >= d[:revoked_at]
          return [nil, ReasonCode::REVOKED, base_evidence]
        end

        if source[:revoked_at] && t >= source[:revoked_at]
          return [nil, ReasonCode::DELEGATION_SOURCE_REVOKED, base_evidence]
        end
        if source_window.before_start?(t)
          return [nil, ReasonCode::DELEGATION_SOURCE_NOT_YET_VALID, base_evidence]
        end
        if source_window.ended?(t)
          return [nil, ReasonCode::DELEGATION_SOURCE_EXPIRED, base_evidence]
        end
        if source[:witness_id].nil? || source[:witness_id].to_s.empty?
          return [nil, ReasonCode::WITNESS_MISSING, base_evidence]
        end

        sub_chain, sub_reason, sub_evidence = find_authorization_chain(
          state, d[:from_supporter_id], source[:person_id], scope, t,
          visited + [d[:from_supporter_id]]
        )

        unless sub_chain
          evidence = (sub_evidence || []) + [deleg_link]
          return [nil, sub_reason || ReasonCode::NO_CONSENT, evidence]
        end

        full_chain = sub_chain + [build_delegation_link(d, source, t)]
        [full_chain, nil, nil]
      end

      def check_budget(d, source, state, t)
        source_budget = emergency_budget_for(source)
        d_budget = d[:emergency_budget_minutes].to_i

        return nil if d_budget <= 0 && source_budget <= 0

        if d_budget > source_budget
          return ReasonCode::DELEGATION_BUDGET_EXCEEDED
        end

        active = state[:delegations].values.select do |other|
          next false if other[:delegation_id] == d[:delegation_id]
          next false unless other[:source_consent_id] == source[:consent_id]
          next false if other[:revoked_at] && t >= other[:revoked_at]
          next false if other[:valid_to] && t >= other[:valid_to]
          next false if t < other[:granted_at]
          next false unless other[:scopes].subset_of?(source[:scopes])
          true
        end

        cumulative = d_budget + active.sum { |o| o[:emergency_budget_minutes].to_i }
        if cumulative > source_budget
          return ReasonCode::DELEGATION_CUMULATIVE_BUDGET_EXCEEDED
        end

        nil
      end

      def emergency_budget_for(source)
        return 0 unless policy && policy.allowed_scope
        return 0 unless source[:scopes].include?(policy.allowed_scope)
        policy.max_minutes
      end

      def find_authorization_chain(state, supporter, person, scope, t, visited)
        direct = state[:consents].values.find do |c|
          c[:supporter_id] == supporter &&
            c[:person_id] == person &&
            check_consent(c, scope, t).nil?
        end
        return [[build_consent_link(direct, t)], nil, nil] if direct

        delegs = state[:delegations].values.select do |d|
          d[:to_supporter_id] == supporter
        end

        reasons = []
        best = [nil, nil, nil]
        delegs.each do |d|
          chain, reason, evidence = walk_delegation(d, state, scope, t, visited)
          return [chain, nil, nil] if chain
          reasons << reason if reason
          if reason && evidence && !evidence.empty?
            prio = ReasonCode::DENIAL_PRIORITY.fetch(reason, -1)
            best_prio = best[1] ? ReasonCode::DENIAL_PRIORITY.fetch(best[1], -1) : -1
            best = [nil, reason, evidence] if prio > best_prio
          end
        end
        [nil, ReasonCode.strongest(reasons), best[2]]
      end

      def evaluate_emergency(state, seen, t)
        scope = request[:scope]
        supporter = request[:supporter_id]

        return nil unless policy && policy.allowed_scope
        return nil unless scope == policy.allowed_scope

        candidate = state[:emergencies]
          .select { |e| e[:scope] == scope && e[:started_at] <= t }
          .max_by { |e| e[:started_at] }

        return nil unless candidate

        prior_consumed = state[:emergencies]
          .select { |e| e[:scope] == scope && e[:started_at] < candidate[:started_at] }
          .sum { |e| e[:consumed_minutes].to_i }

        total_consumed = prior_consumed + candidate[:consumed_minutes].to_i

        if total_consumed > policy.max_minutes
          return DecisionResult.new(
            person_id: request[:person_id], supporter_id: supporter,
            scope: scope, decision_at: t, seen_sequence: seen,
            reason_code: ReasonCode::EMERGENCY_BUDGET_EXHAUSTED, chain: [],
            emergency: emergency_meta(candidate, policy, total_consumed)
          )
        end

        deadline = candidate[:started_at] + (policy.max_minutes * 60)
        within_window = t < deadline

        if within_window
          DecisionResult.new(
            person_id: request[:person_id], supporter_id: supporter,
            scope: scope, decision_at: t, seen_sequence: seen,
            reason_code: ReasonCode::EMERGENCY_AUTHORIZED, chain: [],
            emergency: emergency_meta(candidate, policy, total_consumed),
            consumed_budget_minutes: total_consumed
          )
        else
          DecisionResult.new(
            person_id: request[:person_id], supporter_id: supporter,
            scope: scope, decision_at: t, seen_sequence: seen,
            reason_code: ReasonCode::EMERGENCY_TIMEOUT, chain: [],
            emergency: emergency_meta(candidate, policy, total_consumed).merge(
              "expiredAt" => deadline.iso8601(6)
            )
          )
        end
      end

      def emergency_meta(candidate, policy, total_consumed)
        deadline = candidate[:started_at] + (policy.max_minutes * 60)
        {
          "emergencyId" => candidate[:emergency_id],
          "startedAt" => candidate[:started_at].iso8601(6),
          "deadlineAt" => deadline.iso8601(6),
          "reviewRecorded" => !candidate[:reviewed_at].nil?,
          "reviewRequired" => policy.requires_review_event,
          "consumedMinutes" => candidate[:consumed_minutes].to_i,
          "totalConsumedMinutes" => total_consumed,
          "budgetMinutes" => policy.max_minutes
        }
      end

      def build_consent_link(c, t, redacted: false)
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
          scopes: redacted ? ScopeSet.new([]) : c[:scopes],
          window: window,
          witness_id: redacted ? nil : c[:witness_id],
          occurred_at: c[:granted_at],
          status: status,
          redacted: redacted,
          sequence: c[:sequence]
        )
      end

      def build_delegation_link(d, source, t, redacted: false)
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
          scopes: redacted ? ScopeSet.new([]) : d[:scopes],
          window: TimeWindow.new(d[:granted_at], d[:valid_to]),
          source_consent_id: source ? source[:consent_id] : d[:source_consent_id],
          occurred_at: d[:granted_at],
          status: status,
          redacted: redacted,
          sequence: d[:sequence]
        )
      end
    end
  end
end
