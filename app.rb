require_relative "lib/consent_engine"
require "securerandom"

db_path = ENV.fetch("DB_PATH", File.join(__dir__, "consent_engine.db"))
store = ConsentEngine::Persistence::SqliteEventStore.new(db_path)

seed_path = ENV["SEED"]
if seed_path && File.exist?(seed_path)
  ConsentEngine::SeedLoader.load(store, seed_path)
end

policy = ConsentEngine::Domain::EmergencyPolicy.new(
  allowed_scope: ENV["EMERGENCY_SCOPE"] || "LEGAL_AID_APPLICATION",
  max_minutes: (ENV["EMERGENCY_MAX_MINUTES"] || "30").to_i,
  requires_review_event: ENV["EMERGENCY_REQUIRES_REVIEW"] != "false"
)

ConsentEngine::Api::Server.set :store, store
ConsentEngine::Api::Server.set :policy, policy

if __FILE__ == $0
  port = (ENV["PORT"] || "4567").to_i
  puts "Supported Decision Consent Engine listening on http://0.0.0.0:#{port}"
  puts "Database: #{db_path}"
  puts "Seeded: #{seed_path}" if seed_path
  ConsentEngine::Api::Server.run!(host: "0.0.0.0", port: port)
else
  ConsentEngine::Api::Server
end
