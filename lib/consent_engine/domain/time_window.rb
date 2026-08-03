module ConsentEngine
  module Domain
    class TimeWindow
      attr_reader :from, :to

      def initialize(from_time, to_time)
        @from = from_time
        @to = to_time
      end

      def cover?(t)
        (from.nil? || t >= from) && (to.nil? || t < to)
      end

      def started?(t)
        from.nil? || t >= from
      end

      def before_start?(t)
        !started?(t)
      end

      def ended?(t)
        !to.nil? && t >= to
      end

      def as_json
        {
          "from" => from&.iso8601,
          "to" => to&.iso8601
        }
      end
    end
  end
end
