# frozen_string_literal: true

module ConsentEngine
  # Immutable result of a single authorization decision.
  #
  # +granted+       boolean
  # +reason_code+   stable code from ReasonCodes
  # +scope+         the exact scope that was asked about (echoed back)
  # +chain+         array of ChainLink describing the full grant path
  # +decision_at+   the business time used for the judgement
  # +seen_seq+      max event seq visible to this decision (determinism anchor)
  # +subject_id+    supporter whose authority was evaluated (or nil for emergency)
  class AuthorizationDecision
    attr_reader :granted, :reason_code, :scope, :chain, :decision_at, :seen_seq, :subject_id

    def initialize(granted:, reason_code:, scope:, chain: [], decision_at:, seen_seq:, subject_id: nil)
      @granted     = granted
      @reason_code = reason_code
      @scope       = scope
      @chain       = chain.dup.freeze
      @decision_at = decision_at
      @seen_seq    = seen_seq
      @subject_id  = subject_id
      freeze
    end

    def granted?
      granted
    end

    def to_h
      {
        granted: granted,
        reason_code: reason_code,
        scope: scope,
        subject_id: subject_id,
        decision_at: decision_at.utc.iso8601,
        seen_seq: seen_seq,
        chain: chain.map(&:to_h)
      }
    end
  end

  # One hop in an authorization chain.
  # kind: "PERSON_CONSENT" | "DELEGATION" | "EMERGENCY"
  class ChainLink
    attr_reader :kind, :event_id, :from_id, :to_id, :scopes, :effective_at, :expires_at, :witness_id

    def initialize(kind:, event_id:, from_id:, to_id:, scopes:, effective_at:, expires_at:, witness_id: nil)
      @kind         = kind
      @event_id     = event_id
      @from_id      = from_id
      @to_id        = to_id
      @scopes       = Array(scopes).dup.freeze
      @effective_at = effective_at
      @expires_at   = expires_at
      @witness_id   = witness_id
      freeze
    end

    def to_h
      {
        kind: kind,
        event_id: event_id,
        from_id: from_id,
        to_id: to_id,
        scopes: scopes,
        effective_at: effective_at.utc.iso8601,
        expires_at: expires_at&.utc&.iso8601,
        witness_id: witness_id
      }
    end
  end
end
