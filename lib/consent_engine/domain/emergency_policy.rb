module ConsentEngine
  module Domain
    EmergencyPolicy = Struct.new(:allowed_scope, :max_minutes, :requires_review_event, keyword_init: true)
  end
end
