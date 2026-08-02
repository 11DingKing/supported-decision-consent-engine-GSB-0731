module ConsentEngine
  module Domain
    class AuditEvent
      TYPES = %w[
        ConsentGranted
        ConsentRevoked
        DelegationGranted
        DelegationRevoked
        EmergencyAccessStarted
        EmergencyReviewRecorded
        DecisionRecorded
      ].freeze

      attr_reader :sequence, :event_id, :type, :person_id, :payload, :occurred_at, :recorded_at

      def initialize(sequence:, event_id:, type:, person_id:, payload:, occurred_at:, recorded_at:)
        raise ArgumentError, "unknown event type #{type}" unless TYPES.include?(type)
        @sequence = sequence
        @event_id = event_id
        @type = type
        @person_id = person_id
        @payload = deep_freeze(payload)
        @occurred_at = occurred_at
        @recorded_at = recorded_at
      end

      def as_json
        {
          "sequence" => sequence,
          "eventId" => event_id,
          "type" => type,
          "personId" => person_id,
          "payload" => payload,
          "occurredAt" => occurred_at.iso8601,
          "recordedAt" => recorded_at.iso8601
        }
      end

      private

      def deep_freeze(value)
        case value
        when Hash
          value.each { |k, v| deep_freeze(v) }.freeze
        when Array
          value.each { |v| deep_freeze(v) }.freeze
        else
          value.freeze
        end
        value
      end
    end
  end
end
