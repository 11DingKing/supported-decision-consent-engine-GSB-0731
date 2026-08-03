require_relative "test_helper"

class RevocationRaceTest < Minitest::Test
  def setup
    super
    @store = fresh_store
    @revoke_at = "2026-09-15T10:00:00.000000Z"
    grant_consent(@store, consent_id: "CONSENT-1", supporter: "SUPPORTER-A",
                  scopes: ["LEGAL_AID_APPLICATION", "HOUSING_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z",
                  witness: "W-1", occurred_at: "2026-08-01T00:00:00Z")
  end

  def test_decision_one_microsecond_before_revocation_is_authorized
    one_us_before = "2026-09-15T09:59:59.999999Z"
    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: one_us_before,
      policy: default_policy
    )

    assert result.authorized?,
           "one microsecond before revocation must still be authorized"
    assert_equal "AUTHORIZED", result.reason_code
    assert_equal ["CONSENT-1"], result.chain.map(&:id)
    assert_equal "ACTIVE", result.chain.first.status
  end

  def test_decision_at_exact_revocation_instant_is_revoked
    revoke_consent(@store, revocation_id: "REVOKE-1", consent_id: "CONSENT-1",
                   at: @revoke_at)
    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: @revoke_at,
      policy: default_policy
    )

    refute result.authorized?
    assert_equal "REVOKED", result.reason_code
  end

  def test_decision_one_microsecond_after_revocation_is_revoked
    revoke_consent(@store, revocation_id: "REVOKE-1", consent_id: "CONSENT-1",
                   at: @revoke_at)
    one_us_after = "2026-09-15T10:00:00.000001Z"
    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: one_us_after,
      policy: default_policy
    )

    refute result.authorized?
    assert_equal "REVOKED", result.reason_code
  end

  def test_three_boundary_results_are_stable_and_ordered
    revoke_consent(@store, revocation_id: "REVOKE-1", consent_id: "CONSENT-1",
                   at: @revoke_at)

    before_t = "2026-09-15T09:59:59.999999Z"
    exact_t = @revoke_at
    after_t = "2026-09-15T10:00:00.000001Z"

    before_r = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: before_t, policy: default_policy)
    exact_r = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: exact_t, policy: default_policy)
    after_r = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: after_t, policy: default_policy)

    assert before_r.authorized?
    refute exact_r.authorized?
    refute after_r.authorized?

    assert before_r.seen_sequence < exact_r.seen_sequence ||
           before_r.seen_sequence == exact_r.seen_sequence
    assert_equal "REVOKED", exact_r.reason_code
    assert_equal "REVOKED", after_r.reason_code

    3.times do
      r = @store.evaluate_decision(
        person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
        scope: "LEGAL_AID_APPLICATION", at: before_t, policy: default_policy,
        decision_id: before_r.decision_id)
      assert r.idempotent
      assert_equal before_r.reason_code, r.reason_code
      assert_equal before_r.seen_sequence, r.seen_sequence
    end
  end

  def test_inflight_decision_pinned_before_revoke_stays_authorized_on_replay
    revoke_consent(@store, revocation_id: "REVOKE-1", consent_id: "CONSENT-1",
                   at: @revoke_at)

    inflight = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy
    )
    assert inflight.authorized?
    assert_equal "AUTHORIZED", inflight.reason_code

    verify = @store.verify_replay(inflight.decision_id)
    assert verify[:reason_code_matches]
    assert verify[:chain_matches]
    assert_equal "AUTHORIZED", verify[:recomputed_reason_code]
  end
end

class OutOfOrderRevocationTest < Minitest::Test
  def setup
    super
    @store = fresh_store
    grant_consent(@store, consent_id: "CONSENT-1", supporter: "SUPPORTER-A",
                  scopes: ["LEGAL_AID_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z",
                  witness: "W-1", occurred_at: "2026-08-01T00:00:00Z")
  end

  def test_earlier_revocation_arrives_later_effective_time_is_earliest
    revoke_consent(@store, revocation_id: "REVOKE-LATE", consent_id: "CONSENT-1",
                   at: "2026-09-20T00:00:00Z")
    revoke_consent(@store, revocation_id: "REVOKE-EARLY", consent_id: "CONSENT-1",
                   at: "2026-09-10T00:00:00Z")

    between = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-15T00:00:00Z",
      policy: default_policy
    )

    refute between.authorized?,
           "earlier revocation (late-arriving) must still revoke by 2026-09-15"
    assert_equal "REVOKED", between.reason_code
  end

  def test_out_of_order_revocation_does_not_rewrite_historical_decision
    revoke_consent(@store, revocation_id: "REVOKE-LATE", consent_id: "CONSENT-1",
                   at: "2026-09-20T00:00:00Z")

    historical = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-05T00:00:00Z",
      policy: default_policy
    )
    assert historical.authorized?
    seen_before = historical.seen_sequence

    revoke_consent(@store, revocation_id: "REVOKE-EARLY", consent_id: "CONSENT-1",
                   at: "2026-09-01T00:00:00Z")

    verify = @store.verify_replay(historical.decision_id)
    assert verify[:reason_code_matches],
           "historical decision must not change after late-arriving earlier revocation"
    assert_equal "AUTHORIZED", verify[:recomputed_reason_code]
    assert_equal seen_before, verify[:seen_sequence]
  end

  def test_duplicate_revocation_id_is_idempotent
    revoke_consent(@store, revocation_id: "REVOKE-1", consent_id: "CONSENT-1",
                   at: "2026-09-15T10:00:00Z")
    count_after_first = @store.all_events.length

    revoke_consent(@store, revocation_id: "REVOKE-1", consent_id: "CONSENT-1",
                   at: "2026-09-15T10:00:00Z")
    count_after_second = @store.all_events.length

    assert_equal count_after_first, count_after_second,
                 "duplicate revocation event_id must not create a new event"

    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-16T00:00:00Z",
      policy: default_policy
    )
    assert_equal "REVOKED", result.reason_code
  end
end

class DecisionIdempotencyTest < Minitest::Test
  def setup
    super
    @store = fresh_store
    grant_consent(@store, consent_id: "CONSENT-1", supporter: "SUPPORTER-A",
                  scopes: ["LEGAL_AID_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z",
                  witness: "W-1", occurred_at: "2026-08-01T00:00:00Z")
  end

  def test_repeated_decision_with_same_idempotency_key_returns_same_result
    key = "DEC-IDEMPOTENT-1"
    first = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy, decision_id: key
    )
    events_after_first = @store.all_events.length

    3.times do
      r = @store.evaluate_decision(
        person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
        scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
        policy: default_policy, decision_id: key
      )
      assert r.idempotent
      assert_equal first.decision_id, r.decision_id
      assert_equal first.reason_code, r.reason_code
      assert_equal first.seen_sequence, r.seen_sequence
    end

    assert_equal events_after_first, @store.all_events.length,
                 "repeated submission must not create additional events"
  end

  def test_idempotent_replay_after_revocation_preserves_original_authorization
    key = "DEC-BEFORE-REVOKE"
    before = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy, decision_id: key
    )
    assert before.authorized?

    revoke_consent(@store, revocation_id: "REVOKE-1", consent_id: "CONSENT-1",
                   at: "2026-09-15T10:00:00Z")

    repeated = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy, decision_id: key
    )

    assert repeated.idempotent
    assert repeated.authorized?,
           "idempotent replay must return the original AUTHORIZED, not REVOKED"
    assert_equal "AUTHORIZED", repeated.reason_code
    assert_equal before.seen_sequence, repeated.seen_sequence
  end

  def test_repeated_submission_cannot_expand_scope
    key = "DEC-SCOPE-1"
    @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy, decision_id: key
    )

    assert_raises(ArgumentError) do
      @store.evaluate_decision(
        person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
        scope: "MEDICAL_INFORMATION_VIEW", at: "2026-09-01T00:00:00Z",
        policy: default_policy, decision_id: key
      )
    end
  end

  def test_different_idempotency_keys_produce_independent_decisions
    a = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy, decision_id: "DEC-A"
    )
    b = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
      policy: default_policy, decision_id: "DEC-B"
    )

    refute_equal a.decision_id, b.decision_id
    refute a.idempotent
    refute b.idempotent
  end
end

class EmergencyBudgetAfterRevocationTest < Minitest::Test
  def setup
    super
    @store = fresh_store
    grant_consent(@store, consent_id: "CONSENT-1", supporter: "SUPPORTER-A",
                  scopes: ["LEGAL_AID_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z",
                  witness: "W-1", occurred_at: "2026-08-01T00:00:00Z")
    @responder = "RESPONDER-X"
  end

  def test_emergency_partial_use_then_revoke_consumed_budget_preserved
    start_emergency(@store, emergency_id: "EM-1",
                    scope: "LEGAL_AID_APPLICATION",
                    started_at: "2026-09-14T10:00:00Z",
                    supporter: @responder,
                    source_consent_id: "CONSENT-1",
                    consumed_minutes: 10)

    during = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: @responder,
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-14T10:15:00Z",
      policy: default_policy
    )
    assert during.authorized?
    assert_equal "EMERGENCY_AUTHORIZED", during.reason_code
    assert_equal 10, during.consumed_budget_minutes

    revoke_consent(@store, revocation_id: "REVOKE-1", consent_id: "CONSENT-1",
                   at: "2026-09-15T10:00:00Z")

    after_revoke = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: @responder,
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-14T10:20:00Z",
      policy: default_policy
    )
    assert after_revoke.authorized?,
           "emergency window still open; emergency is the exception after revoke"
    assert_equal "EMERGENCY_AUTHORIZED", after_revoke.reason_code
    assert after_revoke.emergency
    assert_equal 10, after_revoke.emergency["totalConsumedMinutes"],
                 "partially used budget must remain recorded after revocation"
  end

  def test_repeated_emergency_submission_does_not_double_consume_budget
    start_emergency(@store, emergency_id: "EM-DUP",
                    scope: "LEGAL_AID_APPLICATION",
                    started_at: "2026-09-10T10:00:00Z",
                    supporter: @responder,
                    source_consent_id: "CONSENT-1",
                    consumed_minutes: 10)
    start_emergency(@store, emergency_id: "EM-DUP",
                    scope: "LEGAL_AID_APPLICATION",
                    started_at: "2026-09-10T10:00:00Z",
                    supporter: @responder,
                    source_consent_id: "CONSENT-1",
                    consumed_minutes: 10)

    emergency_events = @store.all_events.count do |e|
      e.type == "EmergencyAccessStarted" && e.event_id == "EM-DUP"
    end
    assert_equal 1, emergency_events,
                 "duplicate emergency event_id must not create a second event"

    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: @responder,
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-10T10:15:00Z",
      policy: default_policy
    )
    assert result.authorized?
    assert_equal 10, result.consumed_budget_minutes,
                 "budget consumed must be 10, not 20 from a duplicated submit"
  end

  def test_cumulative_emergency_budget_cannot_exceed_source
    start_emergency(@store, emergency_id: "EM-1",
                    scope: "LEGAL_AID_APPLICATION",
                    started_at: "2026-09-10T10:00:00Z",
                    supporter: @responder,
                    source_consent_id: "CONSENT-1",
                    consumed_minutes: 20)
    start_emergency(@store, emergency_id: "EM-2",
                    scope: "LEGAL_AID_APPLICATION",
                    started_at: "2026-09-11T10:00:00Z",
                    supporter: @responder,
                    source_consent_id: "CONSENT-1",
                    consumed_minutes: 15)

    result = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: @responder,
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-11T10:15:00Z",
      policy: default_policy
    )

    refute result.authorized?
    assert_equal "EMERGENCY_BUDGET_EXHAUSTED", result.reason_code
    assert_equal 35, result.emergency["totalConsumedMinutes"]
  end

  def test_emergency_budget_replay_is_deterministic_after_revoke
    start_emergency(@store, emergency_id: "EM-1",
                    scope: "LEGAL_AID_APPLICATION",
                    started_at: "2026-09-10T10:00:00Z",
                    supporter: @responder,
                    source_consent_id: "CONSENT-1",
                    consumed_minutes: 10)
    decision = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: @responder,
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-10T10:15:00Z",
      policy: default_policy
    )
    assert_equal "EMERGENCY_AUTHORIZED", decision.reason_code
    revoke_consent(@store, revocation_id: "REVOKE-1", consent_id: "CONSENT-1",
                   at: "2026-09-15T10:00:00Z")

    verify = @store.verify_replay(decision.decision_id)
    assert verify[:reason_code_matches]
    assert verify[:chain_matches]
    assert_equal "EMERGENCY_AUTHORIZED", verify[:recomputed_reason_code]
  end

  def test_repeated_submission_cannot_reset_emergency_budget
    start_emergency(@store, emergency_id: "EM-1",
                    scope: "LEGAL_AID_APPLICATION",
                    started_at: "2026-09-10T10:00:00Z",
                    supporter: @responder,
                    source_consent_id: "CONSENT-1",
                    consumed_minutes: 25)

    key = "DEC-EM-IDEM"
    first = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: @responder,
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-10T10:15:00Z",
      policy: default_policy, decision_id: key
    )
    assert first.authorized?
    assert_equal 25, first.consumed_budget_minutes

    3.times do
      r = @store.evaluate_decision(
        person_id: "PERSON-01", supporter_id: @responder,
        scope: "LEGAL_AID_APPLICATION", at: "2026-09-10T10:15:00Z",
        policy: default_policy, decision_id: key
      )
      assert r.idempotent
      assert_equal 25, r.consumed_budget_minutes,
                   "repeated submission must not reset or alter consumed budget"
    end
  end
end

class ConcurrentRevocationRaceTest < Minitest::Test
  def setup
    super
    @store = fresh_store
    grant_consent(@store, consent_id: "CONSENT-1", supporter: "SUPPORTER-A",
                  scopes: ["LEGAL_AID_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z",
                  witness: "W-1", occurred_at: "2026-08-01T00:00:00Z")
  end

  def test_concurrent_revoke_and_inflight_decisions_never_expand_scope
    revoke_at = "2026-09-15T10:00:00.000000Z"
    before = "2026-09-15T09:59:59.999999Z"
    after = "2026-09-15T10:00:00.000001Z"

    threads = 16.times.map do |i|
      Thread.new do
        if i == 0
          revoke_consent(@store, revocation_id: "REVOKE-1",
                         consent_id: "CONSENT-1", at: revoke_at)
        end
        at_time = i.even? ? before : after
        @store.evaluate_decision(
          person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
          scope: "LEGAL_AID_APPLICATION", at: at_time,
          policy: default_policy
        )
      end
    end

    results = threads.map(&:value)

    results.each do |r|
      if r.decision_at.iso8601(6) == before
        assert r.authorized?, "before-revoke decision must be authorized"
        assert_equal "AUTHORIZED", r.reason_code
      else
        refute r.authorized?, "after-revoke decision must not be authorized"
        assert_equal "REVOKED", r.reason_code
      end
    end

    sequences = results.map(&:seen_sequence)
    assert sequences.all? { |s| s.is_a?(Integer) }
  end

  def test_concurrent_idempotent_decisions_produce_single_event
    key = "DEC-CONCURRENT-1"
    at_time = "2026-09-01T00:00:00Z"

    threads = 10.times.map do
      Thread.new do
        @store.evaluate_decision(
          person_id: "PERSON-01", supporter_id: "SUPPORTER-A",
          scope: "LEGAL_AID_APPLICATION", at: at_time,
          policy: default_policy, decision_id: key
        )
      end
    end

    results = threads.map(&:value)
    decision_events = @store.all_events.count do |e|
      e.type == "DecisionRecorded" && e.event_id == key
    end

    assert_equal 1, decision_events,
                 "concurrent idempotent submissions must create exactly one decision"
    assert results.all? { |r| r.reason_code == "AUTHORIZED" }
    assert(results.all? { |r| r.decision_id == key })
  end
end
