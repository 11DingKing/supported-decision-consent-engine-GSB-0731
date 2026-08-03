# frozen_string_literal: true

require "json"

module Consent
  # Canonical JSON serializer: stable key ordering and no incidental
  # whitespace, so the same logical content always produces byte-identical
  # output. Used for the event hash chain and for deterministic responses.
  module CanonicalJSON
    module_function

    def dump(value)
      JSON.generate(canonicalize(value))
    end

    def canonicalize(value)
      case value
      when Hash
        value.keys.map(&:to_s).sort.each_with_object({}) do |k, acc|
          raw = value.key?(k) ? value[k] : value[k.to_sym]
          acc[k] = canonicalize(raw)
        end
      when Array
        value.map { |v| canonicalize(v) }
      else
        value
      end
    end
  end
end
