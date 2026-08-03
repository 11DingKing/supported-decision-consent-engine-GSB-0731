require "time"

module ConsentEngine
  module Clock
    module_function

    def parse_time(value)
      return value if value.is_a?(Time)
      return nil if value.nil?
      Time.iso8601(value.to_s).utc
    end

    def now
      Time.now.utc
    end

    def iso8601(t)
      t.utc.iso8601(6)
    end
  end
end
