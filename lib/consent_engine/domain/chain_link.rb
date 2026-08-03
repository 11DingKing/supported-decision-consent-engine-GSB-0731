module ConsentEngine
  module Domain
    class ChainLink
      attr_reader :kind, :id, :from_subject, :to_supporter_id, :scopes,
                  :window, :witness_id, :source_consent_id, :status, :occurred_at,
                  :redacted, :sequence

      def initialize(kind:, id:, from_subject:, to_supporter_id:, scopes:,
                     window: nil, witness_id: nil, source_consent_id: nil,
                     status: "ACTIVE", occurred_at: nil, redacted: false,
                     sequence: nil)
        @kind = kind
        @id = id
        @from_subject = from_subject
        @to_supporter_id = to_supporter_id
        @scopes = scopes.is_a?(ScopeSet) ? scopes : ScopeSet.new(scopes)
        @window = window
        @witness_id = witness_id
        @source_consent_id = source_consent_id
        @status = status
        @occurred_at = occurred_at
        @redacted = redacted
        @sequence = sequence
      end

      def as_json
        data = {
          "kind" => kind.to_s,
          "id" => id,
          "fromSubject" => from_subject,
          "toSupporterId" => to_supporter_id,
          "status" => status
        }
        if redacted
          data["scopes"] = []
          data["redacted"] = true
        else
          data["scopes"] = scopes.to_a
          data["witnessId"] = witness_id if witness_id
        end
        data["sourceConsentId"] = source_consent_id if source_consent_id
        data["window"] = window.as_json if window
        data["occurredAt"] = occurred_at.iso8601 if occurred_at
        data["sequence"] = sequence if sequence
        data
      end
    end
  end
end
