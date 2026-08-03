module ConsentEngine
  module Domain
    class ScopeSet
      attr_reader :scopes

      def initialize(scopes)
        @scopes = Array(scopes).map(&:to_s).reject(&:empty?).sort.uniq.freeze
      end

      def include?(scope)
        @scopes.include?(scope.to_s)
      end

      def subset_of?(other)
        @scopes.all? { |s| other.include?(s) }
      end

      def intersect?(other)
        @scopes.any? { |s| other.include?(s) }
      end

      def empty?
        @scopes.empty?
      end

      def to_a
        @scopes.dup
      end

      def as_json
        @scopes.dup
      end
    end
  end
end
