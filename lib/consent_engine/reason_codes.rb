# frozen_string_literal: true

module ConsentEngine
  # Stable, immutable reason codes returned by every authorization decision.
  # A reason code MUST NOT change when the same event stream is replayed.
  module ReasonCodes
    # --- Granted (non-zero) ---
    GRANTED                        = "GRANTED"
    GRANTED_VIA_DELEGATION         = "GRANTED_VIA_DELEGATION"
    GRANTED_EMERGENCY              = "GRANTED_EMERGENCY"

    # --- Silent / structural denials (default-deny baseline) ---
    SILENT_NO_CONSENT              = "SILENT_NO_CONSENT"          # no consent record at all
    SCOPE_MISSING                  = "SCOPE_MISSING"              # consent exists but scope absent
    WITNESS_MISSING                = "WITNESS_MISSING"            # consent lacks witness at creation
    PERSON_OR_SUPPORTER_UNKNOWN    = "PERSON_OR_SUPPORTER_UNKNOWN"

    # --- Time-window denials ---
    NOT_YET_VALID                  = "NOT_YET_VALID"              # from > decision time
    EXPIRED                        = "EXPIRED"                    # to <= decision time

    # --- Revocation ---
    REVOKED                        = "REVOKED"                    # explicit revoke at/before decision
    REVOKED_BEFORE_GRANT           = "REVOKED_BEFORE_GRANT"       # revoke predates the grant

    # --- Delegation chain denials ---
    DELEGATION_CYCLE               = "DELEGATION_CYCLE"
    DELEGATION_BROAD               = "DELEGATION_BROAD"           # delegated scope exceeds source
    DELEGATION_EXPIRED             = "DELEGATION_EXPIRED"         # delegation own to <= decision
    DELEGATION_SOURCE_EXPIRED      = "DELEGATION_SOURCE_EXPIRED"  # source consent to <= decision
    DELEGATION_SOURCE_REVOKED      = "DELEGATION_SOURCE_REVOKED"  # source consent revoked at/before decision
    DELEGATION_BEFORE_SOURCE       = "DELEGATION_BEFORE_SOURCE"   # delegation event predates source grant
    DELEGATION_SOURCE_SCOPE_MISSING= "DELEGATION_SOURCE_SCOPE_MISSING"

    # --- Round 2: concurrent sub-delegation / cumulative budget / seq-order ---
    # Generic, non-scope-leaking denial returned to a sub-delegation holder
    # whose chain is structurally invalid. The detailed reason is retained in
    # the immutable audit chain but NOT exposed in the top-level code, so an
    # attacker cannot enumerate which scopes a source does or does not have.
    DELEGATION_DENIED              = "DELEGATION_DENIED"
    # A sub-delegation was appended (seq) AFTER a revocation of its source,
    # even though its business effective_at claims to be earlier. The audit
    # sequence makes this impossible to accept.
    DELEGATION_AFTER_REVOCATION    = "DELEGATION_AFTER_REVOCATION"
    # Two or more sibling sub-delegations from the same source together
    # exceed the source's delegated budget (scope count, time window, or
    # emergency minutes).
    DELEGATION_BUDGET_EXCEEDED     = "DELEGATION_BUDGET_EXCEEDED"
    # A sub-delegation arrived too late to be evaluated against the source
    # state it claims; it must be rejected to preserve determinism.
    DELEGATION_LATE                = "DELEGATION_LATE"

    # --- Emergency ---
    EMERGENCY_SCOPE_NOT_ALLOWED    = "EMERGENCY_SCOPE_NOT_ALLOWED"
    EMERGENCY_TIMEOUT              = "EMERGENCY_TIMEOUT"
    EMERGENCY_WITHOUT_REVIEW_EVENT = "EMERGENCY_WITHOUT_REVIEW_EVENT"

    # --- Concurrency / determinism guard ---
    EVENT_FROM_FUTURE              = "EVENT_FROM_FUTURE"          # decision as_of before an event it saw

    ALL = constants.map { |c| const_get(c) }.freeze
  end
end
