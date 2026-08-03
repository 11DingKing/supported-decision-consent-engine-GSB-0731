require_relative "consent_engine/clock"
require_relative "consent_engine/domain/reason_code"
require_relative "consent_engine/domain/time_window"
require_relative "consent_engine/domain/scope_set"
require_relative "consent_engine/domain/audit_event"
require_relative "consent_engine/domain/chain_link"
require_relative "consent_engine/domain/decision_result"
require_relative "consent_engine/domain/emergency_policy"
require_relative "consent_engine/domain/consent_boundary"
require_relative "consent_engine/persistence/sqlite_event_store"
require_relative "consent_engine/seed_loader"
require_relative "consent_engine/api/server"

module ConsentEngine
  VERSION = "1.0.0"
end
