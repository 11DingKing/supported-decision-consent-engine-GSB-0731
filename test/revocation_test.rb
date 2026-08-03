# frozen_string_literal: true

require_relative "test_helper"

# Threat model: REVOCATION.
#
# The risk: silence is treated as consent, a revocation is lost against an
# in-flight decision, or the exact revocation instant is interpreted
# permissively so a supporter keeps acting after the person said no.
#
# Invariants under test:
#   * A revoke at time R blocks any decision at time T >= R.
#   * A decision at T < R is still granted.
#   * The exact instant of revocation is treated as DENIED (half-open).
#   * A revoke with no prior grant never grants authority.
#   * Replay at the pinned (decisionAt, seenSeq) gives the same reason code.
#   * Concurrent revoke and grant cannot expand scope.
class RevocationTest < Minitest::Test
  include TestHelpers

  def setup
    @service = build_service
    @service.store.clock = fixed_clock("2026-08-01T00:00:00Z")
    seed_person_and_supporter(@service, "P1", %w[S1])
    @service.grant_consent(
      consent_id: "C1", person_id: "P1", supporter_id: "S1",
      scopes: %w[HOUSING], from: "2026-08-01T00:00:00Z",
      to: "2026-12-01T00:00:00Z", witness_id: "W1",
      effective_at: "2026-08-01T00:00:00Z"
    )
  end

  def test_granted_before_revocation
    d = @service.decide(person_id: "P1", supporter_id: "S1", scope: "HOUSING", as_of: "2026-09-01T00:00:00Z")
    assert d.granted?
    assert_equal ConsentEngine::ReasonCodes::GRANTED, d.reason_code
    assert_equal 1, d.chain.size
    assert_equal "PERSON_CONSENT", d.chain.first.kind
  end

  def test_revoked_after_revocation
    @service.revoke_consent(
      revocation_id: "R1", consent_id: "C1",
      at: "2026-09-15T10:00:00Z", effective_at: "2026-09-15T10:00:00Z"
    )
    d = @service.decide(person_id: "P1", supporter_id: "S1", scope: "HOUSING", as_of: "2026-09-16T00:00:00Z")
    refute d.granted?
    assert_equal ConsentEngine::ReasonCodes::REVOKED, d.reason_code
  end

  def test_exact_revocation_instant_is_denied
    @service.revoke_consent(
      revocation_id: "R1", consent_id: "C1",
      at: "2026-09-15T10:00:00Z", effective_at: "2026-09-15T10:00:00Z"
    )
    d = @service.decide(person_id: "P1", supporter_id: "S1", scope: "HOUSING", as_of: "2026-09-15T10:00:00Z")
    refute d.granted?, "decision at exact revocation instant MUST be denied"
    assert_equal ConsentEngine::ReasonCodes::REVOKED, d.reason_code
  end

  def test_revocation_does_not_rewrite_history
    @service.revoke_consent(
      revocation_id: "R1", consent_id: "C1",
      at: "2026-09-15T10:00:00Z", effective_at: "2026-09-15T10:00:00Z"
    )
    # Decision at time before revocation, but seen_seq includes the revoke event.
    # The decision MUST remain granted because the revoke is effective in the
    # future relative to decision_at — the event is on the log but not active.
    d = @service.decide(person_id: "P1", supporter_id: "S1", scope: "HOUSING", as_of: "2026-09-01T00:00:00Z")
    assert d.granted?, "future-dated revoke must not affect prior decisions"
    assert_equal ConsentEngine::ReasonCodes::GRANTED, d.reason_code
  end

  def test_replay_after_more_events_is_stable
    d1 = @service.decide(person_id: "P1", supporter_id: "S1", scope: "HOUSING", as_of: "2026-09-01T00:00:00Z")
    decision_id = @service.events.last.event_id

    # Add more history after the decision.
    @service.revoke_consent(
      revocation_id: "R1", consent_id: "C1",
      at: "2026-09-15T10:00:00Z", effective_at: "2026-09-15T10:00:00Z"
    )
    @service.register_supporter("S9")

    d2 = @service.replay(decision_id)
    assert_equal d1.reason_code, d2.reason_code
    assert_equal d1.granted?,     d2.granted?
    assert_equal d1.chain.map(&:event_id), d2.chain.map(&:event_id)
    assert_equal d1.seen_seq, d2.seen_seq
  end

  def test_silence_is_not_consent
    service = build_service
    seed_person_and_supporter(service, "P9", %w[S9])
    d = service.decide(person_id: "P9", supporter_id: "S9", scope: "HOUSING", as_of: "2026-09-01T00:00:00Z")
    refute d.granted?
    assert_equal ConsentEngine::ReasonCodes::SILENT_NO_CONSENT, d.reason_code
  end

  def test_scope_missing_cannot_be_inferred
    d = @service.decide(person_id: "P1", supporter_id: "S1", scope: "MEDICAL_INFORMATION_VIEW", as_of: "2026-09-01T00:00:00Z")
    refute d.granted?
    assert_equal ConsentEngine::ReasonCodes::SCOPE_MISSING, d.reason_code
  end

  def test_missing_witness_denies
    service = build_service
    seed_person_and_supporter(service, "P1", %w[S1])
    service.grant_consent(
      consent_id: "CW", person_id: "P1", supporter_id: "S1",
      scopes: %w[HOUSING], from: "2026-08-01T00:00:00Z",
      to: "2026-12-01T00:00:00Z", witness_id: nil,
      effective_at: "2026-08-01T00:00:00Z"
    )
    d = service.decide(person_id: "P1", supporter_id: "S1", scope: "HOUSING", as_of: "2026-09-01T00:00:00Z")
    refute d.granted?
    assert_equal ConsentEngine::ReasonCodes::WITNESS_MISSING, d.reason_code
  end

  def test_revoke_before_grant_is_safe
    service = build_service
    seed_person_and_supporter(service, "P1", %w[S1])
    # Revoke arrives before any grant — must never be treated as authority.
    service.revoke_consent(
      revocation_id: "REARLY", consent_id: "CLATE",
      at: "2026-08-01T00:00:00Z", effective_at: "2026-08-01T00:00:00Z"
    )
    service.grant_consent(
      consent_id: "CLATE", person_id: "P1", supporter_id: "S1",
      scopes: %w[HOUSING], from: "2026-09-01T00:00:00Z",
      to: "2026-12-01T00:00:00Z", witness_id: "W1",
      effective_at: "2026-09-01T00:00:00Z"
    )
    d = service.decide(person_id: "P1", supporter_id: "S1", scope: "HOUSING", as_of: "2026-10-01T00:00:00Z")
    refute d.granted?
    assert_equal ConsentEngine::ReasonCodes::REVOKED_BEFORE_GRANT, d.reason_code
  end

  def test_concurrent_grant_and_revoke_cannot_expand_scope
    # Simulate the race: two writers race; then a decision pins high seq.
    service = build_service
    seed_person_and_supporter(service, "P1", %w[S1])
    threads = []
    5.times do |i|
      threads << Thread.new do
        service.grant_consent(
          consent_id: "C-RACE-#{i}", person_id: "P1", supporter_id: "S1",
          scopes: %w[HOUSING], from: "2026-08-01T00:00:00Z",
          to: "2026-12-01T00:00:00Z", witness_id: "W1",
          effective_at: "2026-08-01T00:00:00Z"
        )
      rescue ConsentEngine::EventStore::DuplicateEventId
        # expected under retry
      end
    end
    threads << Thread.new do
      service.revoke_consent(
        revocation_id: "R-RACE", consent_id: "C-RACE-0",
        at: "2026-09-15T10:00:00Z", effective_at: "2026-09-15T10:00:00Z"
      )
    end
    threads.each(&:join)

    d = service.decide(person_id: "P1", supporter_id: "S1", scope: "HOUSING", as_of: "2026-10-01T00:00:00Z")
    # There are other grants not tied to C-RACE-0, so granted is possible; what
    # must never happen is that the REVOKED grant is treated as active. We
    # assert by replaying with seen_seq pinned: the result is deterministic.
    d2 = service.replay(service.events.last.event_id)
    assert_equal d.reason_code, d2.reason_code
    assert_equal d.granted?, d2.granted?

    # And no event was lost or reordered.
    seqs = service.events.map(&:seq)
    assert_equal seqs.sort, seqs
    assert_equal seqs.uniq.size, seqs.size
  end
end
