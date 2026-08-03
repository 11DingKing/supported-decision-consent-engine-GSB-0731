require_relative "test_helper"

class SubDelegationConcurrencyTest < Minitest::Test
  def setup
    super
    @store = fresh_store
    grant_consent(@store, consent_id: "CONSENT-1", supporter: "SUPPORTER-A",
                  scopes: ["LEGAL_AID_APPLICATION", "HOUSING_APPLICATION"],
                  from: "2026-08-01T00:00:00Z", to: "2026-12-01T00:00:00Z",
                  witness: "W-1", occurred_at: "2026-08-01T00:00:00Z")
  end

  def test_concurrent_sub_delegations_never_expand_budget
    threads = 8.times.map do |i|
      Thread.new do
        begin
          delegate(@store,
                   delegation_id: "D-CONC-#{i}",
                   source_consent: "CONSENT-1",
                   from_sup: "SUPPORTER-A",
                   to_sup: "SUPPORTER-#{i}",
                   scopes: ["LEGAL_AID_APPLICATION"],
                   occurred_at: "2026-08-02T00:0#{i}:00Z",
                   valid_to: "2026-10-01T00:00:00Z",
                   emergency_budget_minutes: 10)
        rescue
        end
        @store.evaluate_decision(
          person_id: "PERSON-01", supporter_id: "SUPPORTER-#{i}",
          scope: "LEGAL_AID_APPLICATION", at: "2026-09-01T00:00:00Z",
          policy: default_policy
        )
      end
    end

    results = threads.map(&:value)
    sequences = @store.all_events.map(&:sequence)

    assert_equal sequences, sequences.sort
    assert_equal sequences.uniq, sequences

    results.each do |r|
      assert r.is_a?(ConsentEngine::Domain::DecisionResult)
      if r.authorized?
        assert_equal "AUTHORIZED", r.reason_code
      else
        assert_equal "DELEGATION_CUMULATIVE_BUDGET_EXCEEDED", r.reason_code
      end
    end

    authorized_count = results.count(&:authorized?)
    assert authorized_count <= 3,
           "source budget is 30 min, at most three 10-min delegations may be authorized, got #{authorized_count}"
  end

  def test_concurrent_grant_and_revoke_with_late_delegation
    barrier = Queue.new

    grant_thread = Thread.new do
      delegate(@store,
               delegation_id: "D-RACE",
               source_consent: "CONSENT-1",
               from_sup: "SUPPORTER-A",
               to_sup: "SUPPORTER-B",
               scopes: ["LEGAL_AID_APPLICATION"],
               occurred_at: "2026-08-02T00:00:00Z",
               valid_to: "2026-10-01T00:00:00Z")
      barrier << :granted
    end

    revoke_thread = Thread.new do
      barrier.pop
      revoke_consent(@store, revocation_id: "REV-RACE",
                     consent_id: "CONSENT-1", at: "2026-09-15T10:00:00Z")
    end

    grant_thread.join
    revoke_thread.join

    late_thread = Thread.new do
      delegate(@store,
               delegation_id: "D-LATE-RACE",
               source_consent: "CONSENT-1",
               from_sup: "SUPPORTER-A",
               to_sup: "SUPPORTER-C",
               scopes: ["LEGAL_AID_APPLICATION"],
               occurred_at: "2026-08-10T00:00:00Z",
               valid_to: "2026-10-01T00:00:00Z")
    end
    late_thread.join

    after_revoke = @store.evaluate_decision(
      person_id: "PERSON-01", supporter_id: "SUPPORTER-C",
      scope: "LEGAL_AID_APPLICATION", at: "2026-09-20T00:00:00Z",
      policy: default_policy
    )

    refute after_revoke.authorized?
    assert_equal "DELEGATION_LATE_ARRIVAL", after_revoke.reason_code
    assert after_revoke.chain.all?(&:redacted)
  end

  def test_concurrent_broad_delegations_never_authorize
    threads = 6.times.map do |i|
      Thread.new do
        begin
          delegate(@store,
                   delegation_id: "D-BROAD-#{i}",
                   source_consent: "CONSENT-1",
                   from_sup: "SUPPORTER-A",
                   to_sup: "SUPPORTER-B#{i}",
                   scopes: ["MEDICAL_INFORMATION_VIEW"],
                   occurred_at: "2026-08-02T00:0#{i}:00Z")
        rescue
        end
        @store.evaluate_decision(
          person_id: "PERSON-01", supporter_id: "SUPPORTER-B#{i}",
          scope: "MEDICAL_INFORMATION_VIEW", at: "2026-09-01T00:00:00Z",
          policy: default_policy
        )
      end
    end

    results = threads.map(&:value)
    results.each do |r|
      refute r.authorized?
      assert_equal "DELEGATION_BROADER_THAN_SOURCE", r.reason_code
      assert r.chain.all?(&:redacted), "denied evidence must not leak scope"
      assert r.chain.all? { |l| l.scopes.to_a.empty? }
    end
  end
end
