module ConsentEngine
  module Domain
    class DecisionResult
      attr_reader :person_id, :supporter_id, :scope, :decision_at,
                  :seen_sequence, :reason_code, :chain, :emergency,
                  :decision_id, :idempotent, :consumed_budget_minutes

      def initialize(person_id:, supporter_id:, scope:, decision_at:,
                     seen_sequence:, reason_code:, chain: [], emergency: nil,
                     decision_id: nil, idempotent: false,
                     consumed_budget_minutes: nil)
        @person_id = person_id
        @supporter_id = supporter_id
        @scope = scope
        @decision_at = decision_at
        @seen_sequence = seen_sequence
        @reason_code = reason_code
        @chain = chain
        @emergency = emergency
        @decision_id = decision_id
        @idempotent = idempotent
        @consumed_budget_minutes = consumed_budget_minutes
      end

      def authorized?
        ReasonCode.authorized?(reason_code)
      end

      def as_json
        data = {
          "decisionId" => decision_id,
          "personId" => person_id,
          "supporterId" => supporter_id,
          "scope" => scope,
          "decisionAt" => decision_at.utc.iso8601(6),
          "seenSequence" => seen_sequence,
          "authorized" => authorized?,
          "reasonCode" => reason_code,
          "idempotent" => idempotent,
          "chain" => chain.map(&:as_json)
        }
        data["emergency"] = emergency if emergency
        data["consumedBudgetMinutes"] = consumed_budget_minutes unless consumed_budget_minutes.nil?
        data
      end
    end
  end
end
