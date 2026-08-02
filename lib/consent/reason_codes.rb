# frozen_string_literal: true

module Consent
  # Stable, machine-readable reason codes returned by the authorization engine.
  #
  # These strings are part of the API contract: given a fixed (event_time,
  # audit_seq) pair, replaying an evaluation must always yield the same code.
  # Codes are therefore never reworded or reordered by evaluation-time state;
  # they are selected purely from the recorded facts.
  module ReasonCodes
    # --- Authorized outcomes ------------------------------------------------
    AUTHORIZED_DIRECT_CONSENT    = "AUTHORIZED_DIRECT_CONSENT"
    AUTHORIZED_DELEGATED_CONSENT = "AUTHORIZED_DELEGATED_CONSENT"
    AUTHORIZED_EMERGENCY         = "AUTHORIZED_EMERGENCY"

    # --- Denied outcomes ----------------------------------------------------
    NO_CONSENT                       = "NO_CONSENT"
    SCOPE_NOT_IN_CONSENT             = "SCOPE_NOT_IN_CONSENT"
    CONSENT_NOT_YET_EFFECTIVE        = "CONSENT_NOT_YET_EFFECTIVE"
    CONSENT_EXPIRED                  = "CONSENT_EXPIRED"
    CONSENT_REVOKED                  = "CONSENT_REVOKED"
    CONSENT_NOT_WITNESSED            = "CONSENT_NOT_WITNESSED"
    DELEGATION_EXPIRED               = "DELEGATION_EXPIRED"
    DELEGATION_NOT_YET_EFFECTIVE     = "DELEGATION_NOT_YET_EFFECTIVE"
    DELEGATION_REVOKED               = "DELEGATION_REVOKED"
    DELEGATION_SCOPE_EXCEEDS_SOURCE  = "DELEGATION_SCOPE_EXCEEDS_SOURCE"
    DELEGATION_DURATION_EXCEEDS_SOURCE = "DELEGATION_DURATION_EXCEEDS_SOURCE"
    DELEGATION_BUDGET_EXCEEDS_SOURCE = "DELEGATION_BUDGET_EXCEEDS_SOURCE"
    DELEGATION_BUDGET_EXCEEDED       = "DELEGATION_BUDGET_EXCEEDED"
    DELEGATION_SOURCE_AUTHORITY_MISSING = "DELEGATION_SOURCE_AUTHORITY_MISSING"
    DELEGATION_CYCLE                 = "DELEGATION_CYCLE"
    SOURCE_CONSENT_INVALID           = "SOURCE_CONSENT_INVALID"
    EMERGENCY_SCOPE_NOT_ALLOWED      = "EMERGENCY_SCOPE_NOT_ALLOWED"
    EMERGENCY_EXPIRED                = "EMERGENCY_EXPIRED"
    EMERGENCY_REVOKED                = "EMERGENCY_REVOKED"
    EMERGENCY_BUDGET_EXHAUSTED       = "EMERGENCY_BUDGET_EXHAUSTED"
    EMERGENCY_NOT_YET_EFFECTIVE      = "EMERGENCY_NOT_YET_EFFECTIVE"
    EMERGENCY_REVIEW_MISSING         = "EMERGENCY_REVIEW_MISSING"
    UNKNOWN_SUPPORTER                = "UNKNOWN_SUPPORTER"
    UNKNOWN_SCOPE                    = "UNKNOWN_SCOPE"

    AUTHORIZED = [
      AUTHORIZED_DIRECT_CONSENT,
      AUTHORIZED_DELEGATED_CONSENT,
      AUTHORIZED_EMERGENCY
    ].freeze

    # Denial precedence, most specific first. When several candidate authority
    # paths all fail, the engine reports the failure that sits earliest in this
    # list. The order is fixed so replays are stable and so that a structural
    # error (a cycle) or an explicit withdrawal is never masked by a vaguer
    # "no consent" style answer.
    DENIAL_PRECEDENCE = [
      DELEGATION_CYCLE,
      CONSENT_REVOKED,
      DELEGATION_REVOKED,
      EMERGENCY_REVOKED,
      SOURCE_CONSENT_INVALID,
      DELEGATION_SCOPE_EXCEEDS_SOURCE,
      DELEGATION_DURATION_EXCEEDS_SOURCE,
      DELEGATION_BUDGET_EXCEEDS_SOURCE,
      DELEGATION_BUDGET_EXCEEDED,
      DELEGATION_SOURCE_AUTHORITY_MISSING,
      CONSENT_EXPIRED,
      DELEGATION_EXPIRED,
      EMERGENCY_EXPIRED,
      EMERGENCY_BUDGET_EXHAUSTED,
      EMERGENCY_REVIEW_MISSING,
      EMERGENCY_SCOPE_NOT_ALLOWED,
      CONSENT_NOT_WITNESSED,
      CONSENT_NOT_YET_EFFECTIVE,
      DELEGATION_NOT_YET_EFFECTIVE,
      EMERGENCY_NOT_YET_EFFECTIVE,
      SCOPE_NOT_IN_CONSENT,
      UNKNOWN_SUPPORTER,
      UNKNOWN_SCOPE,
      NO_CONSENT
    ].freeze

    def self.authorized?(code)
      AUTHORIZED.include?(code)
    end

    # Deterministic selection of the winning denial among candidates.
    def self.most_specific_denial(codes)
      present = codes.compact.uniq
      return NO_CONSENT if present.empty?

      present.min_by do |code|
        idx = DENIAL_PRECEDENCE.index(code)
        idx || DENIAL_PRECEDENCE.length
      end
    end
  end
end
