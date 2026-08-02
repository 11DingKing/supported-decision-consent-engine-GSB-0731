# frozen_string_literal: true

require_relative "consent/instant"
require_relative "consent/canonical_json"
require_relative "consent/reason_codes"
require_relative "consent/event"
require_relative "consent/event_store"
require_relative "consent/projection"
require_relative "consent/engine"
require_relative "consent/ledger"
require_relative "consent/seed"

module Consent
  VERSION = "1.0.0"
end
