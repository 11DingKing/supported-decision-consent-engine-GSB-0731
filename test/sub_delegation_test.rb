# frozen_string_literal: true

require_relative "test_helper"

# THREAT MODEL (round 2): Concurrent sub-delegation from a single source
# authority.
#
# Danger: two supporters receive sub-delegations drawing on the SAME source
# consent, and — through scope creep, a longer window, an oversized emergency
# budget, or two siblings that individually fit but TOGETHER exceed the source
# — end up wielding more authority than the source ever held. The race makes it
# worse: one sub-delegation is revoked before its branch is saved while another
# arrives late, so a naive engine double-counts or under-counts the shared
# budget.
#
# Defence: a sub-delegation may never grant more than its source. Scope,
# duration and per-link budget are each capped against the source, and sibling
# sub-delegations share ONE cumulative budget accounted greedily in created_seq
# order over the siblings valid as-of (eventTime, asOfSeq). Validity is a pure
# function of those anchors, so revoke-before-save / delayed-arrival resolve to
# a stable answer. Denied sub-chains still return authority-chain evidence with
# every scope field REDACTED.
#
# Reuses round-1 identifiers: CONSENT-1, SUPPORTER-A/B, DELEG-OK, DELEG-BROAD,
# scopes HOUSING/LEGAL_AID/MEDICAL, witness W-1, and audit-seq ordering.
class SubDelegationTest < Minitest::Test
  include TestSupport

  R = Consent::ReasonCodes

  T0 = "2026-08-01T00:00:00Z"  # CONSENT-1 effective from
  T1 = "2026-09-01T00:00:00Z"  # comfortably inside every window
  SOURCE_TO = "2026-12-01T00:00:00Z" # CONSENT-1 to

  # A source consent that mirrors CONSENT-1 but carries an emergency budget, so
  # budget caps can be exercised while reusing the round-1 id vocabulary.
  def budgeted_source
    l = fresh_ledger
    l.register_person("PERSON-01")
    %w[HOUSING_APPLICATION LEGAL_AID_APPLICATION MEDICAL_INFORMATION_VIEW].each { |s| l.define_scope(s) }
    %w[SUPPORTER-A SUPPORTER-B SUPPORTER-C].each { |s| l.add_supporter(s) }
    l.grant_consent(id: "CONSENT-1", supporter_id: "SUPPORTER-A",
                    scopes: %w[LEGAL_AID_APPLICATION HOUSING_APPLICATION],
                    from: T0, to: SOURCE_TO, witness_id: "W-1",
                    emergency_budget_minutes: 30)
    l
  end

  def decide(l, supporter, scope, at, as_of_seq: nil)
    l.evaluate(supporter_id: supporter, scope: scope, at: at, as_of_seq: as_of_seq)
  end

  # --- Baseline: DELEG-OK still authorizes, DELEG-BROAD still denied --------

  def test_deleg_ok_still_authorizes_with_caps_in_place
    l = seeded_ledger
    d = decide(l, "SUPPORTER-B", "LEGAL_AID_APPLICATION", T1)
    assert d.authorized
    assert_equal R::AUTHORIZED_DELEGATED_CONSENT, d.reason_code
    assert_equal %w[consent delegation], d.authority_chain.map { |x| x["type"] }
    assert_equal "DELEG-OK", d.authority_chain.last["delegationId"]
  end

  def test_deleg_broad_denied_with_redacted_evidence
    l = seeded_ledger
    d = decide(l, "SUPPORTER-B", "MEDICAL_INFORMATION_VIEW", T1)
    refute d.authorized
    assert_equal R::DELEGATION_SCOPE_EXCEEDS_SOURCE, d.reason_code
    assert_scope_redacted(d.authority_chain)
    # Evidence still names the broken delegation link structurally.
    assert(d.authority_chain.any? { |l| l["delegationId"] == "DELEG-BROAD" })
  end

  # --- Duration cap -------------------------------------------------------

  def test_sub_delegation_window_within_source_authorizes
    l = budgeted_source
    l.create_delegation(id: "DELEG-OK", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                        scopes: ["LEGAL_AID_APPLICATION"],
                        from: T0, to: "2026-10-01T00:00:00Z")
    d = decide(l, "SUPPORTER-B", "LEGAL_AID_APPLICATION", T1)
    assert d.authorized, d.reason_code
  end

  def test_sub_delegation_window_exceeds_source_denied
    l = budgeted_source
    # `to` reaches beyond CONSENT-1's 2026-12-01 end.
    l.create_delegation(id: "DELEG-LONG", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                        scopes: ["LEGAL_AID_APPLICATION"],
                        from: T0, to: "2027-06-01T00:00:00Z")
    d = decide(l, "SUPPORTER-B", "LEGAL_AID_APPLICATION", T1)
    refute d.authorized
    assert_equal R::DELEGATION_DURATION_EXCEEDS_SOURCE, d.reason_code
    assert_scope_redacted(d.authority_chain)
  end

  # --- Per-link emergency budget cap --------------------------------------

  def test_sub_delegation_budget_within_source_authorizes
    l = budgeted_source
    l.create_delegation(id: "DELEG-B1", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                        scopes: ["LEGAL_AID_APPLICATION"], budget_minutes: 20)
    d = decide(l, "SUPPORTER-B", "LEGAL_AID_APPLICATION", T1)
    assert d.authorized, d.reason_code
  end

  def test_sub_delegation_budget_exceeds_source_denied
    l = budgeted_source # source budget = 30
    l.create_delegation(id: "DELEG-BIG", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                        scopes: ["LEGAL_AID_APPLICATION"], budget_minutes: 45)
    d = decide(l, "SUPPORTER-B", "LEGAL_AID_APPLICATION", T1)
    refute d.authorized
    assert_equal R::DELEGATION_BUDGET_EXCEEDS_SOURCE, d.reason_code
    assert_scope_redacted(d.authority_chain)
  end

  # --- Cumulative sibling budget ------------------------------------------

  def test_two_sub_chains_individually_fit_but_cumulatively_exceed
    l = budgeted_source # source budget = 30
    # Two siblings on the SAME source consent: 20 + 20 = 40 > 30.
    l.create_delegation(id: "DELEG-S1", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                        scopes: ["LEGAL_AID_APPLICATION"], budget_minutes: 20)
    l.create_delegation(id: "DELEG-S2", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-C",
                        scopes: ["LEGAL_AID_APPLICATION"], budget_minutes: 20)
    # First sibling (lower seq) fits within the running total.
    d1 = decide(l, "SUPPORTER-B", "LEGAL_AID_APPLICATION", T1)
    assert d1.authorized, d1.reason_code
    # Second sibling pushes the cumulative total over the shared source budget.
    d2 = decide(l, "SUPPORTER-C", "LEGAL_AID_APPLICATION", T1)
    refute d2.authorized
    assert_equal R::DELEGATION_BUDGET_EXCEEDED, d2.reason_code
    assert_scope_redacted(d2.authority_chain)
  end

  # --- The race: revoke-before-save + delayed arrival ---------------------

  def test_revoked_sibling_frees_cumulative_budget
    # Sibling S1 (20) is created, then REVOKED before S2's branch is decided;
    # a delayed third sibling S3 (20) arrives afterwards. As-of a time when S1
    # is revoked, only S2 + S3 count (20 + 20 = 40 > 30): S3 overflows, but S2
    # fits because S1 no longer holds budget. Nothing is double-counted.
    l = budgeted_source # budget = 30
    l.add_supporter("SUPPORTER-D")
    l.create_delegation(id: "DELEG-S1", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                        scopes: ["LEGAL_AID_APPLICATION"], budget_minutes: 20,
                        from: T0)
    l.create_delegation(id: "DELEG-S2", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-C",
                        scopes: ["LEGAL_AID_APPLICATION"], budget_minutes: 20,
                        from: T0)
    # S1 revoked at 2026-09-10 (before the decision instant below).
    l.revoke_delegation(delegation_id: "DELEG-S1", at: "2026-09-10T00:00:00Z")
    # Delayed arrival: S3 recorded last, to a distinct supporter.
    l.create_delegation(id: "DELEG-S3", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-D",
                        scopes: ["LEGAL_AID_APPLICATION"], budget_minutes: 20,
                        from: T0)

    at = "2026-09-20T00:00:00Z" # S1 already revoked here
    # S2 fits: S1 freed its 20, so running total for S2 = 20 <= 30.
    d2 = decide(l, "SUPPORTER-C", "LEGAL_AID_APPLICATION", at)
    assert d2.authorized, d2.reason_code
    # S3 (via SUPPORTER-D) overflows: S2(20) + S3(20) = 40 > 30.
    d3 = decide(l, "SUPPORTER-D", "LEGAL_AID_APPLICATION", at)
    refute d3.authorized
    assert_equal R::DELEGATION_BUDGET_EXCEEDED, d3.reason_code
  end

  def test_before_revocation_seq_both_original_siblings_accounted
    # Pin asOfSeq to before the revocation and before S3: only S1 + S2 exist
    # (20 + 20 = 40 > 30). S1 fits, S2 overflows — the historical answer.
    l = budgeted_source
    l.create_delegation(id: "DELEG-S1", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                        scopes: ["LEGAL_AID_APPLICATION"], budget_minutes: 20, from: T0)
    l.create_delegation(id: "DELEG-S2", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-C",
                        scopes: ["LEGAL_AID_APPLICATION"], budget_minutes: 20, from: T0)
    seq_after_two = l.max_seq
    l.revoke_delegation(delegation_id: "DELEG-S1", at: "2026-09-10T00:00:00Z")

    at = "2026-09-20T00:00:00Z"
    d1 = decide(l, "SUPPORTER-B", "LEGAL_AID_APPLICATION", at, as_of_seq: seq_after_two)
    assert d1.authorized, d1.reason_code
    d2 = decide(l, "SUPPORTER-C", "LEGAL_AID_APPLICATION", at, as_of_seq: seq_after_two)
    refute d2.authorized
    assert_equal R::DELEGATION_BUDGET_EXCEEDED, d2.reason_code
  end

  def test_delayed_sibling_not_visible_below_its_seq
    # A late-arriving sibling must not retroactively consume budget for a
    # decision pinned to an earlier audit seq.
    l = budgeted_source
    l.create_delegation(id: "DELEG-S1", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                        scopes: ["LEGAL_AID_APPLICATION"], budget_minutes: 25, from: T0)
    seq_one = l.max_seq
    # Late sibling would push 25 + 20 = 45 > 30.
    l.create_delegation(id: "DELEG-S2", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-C",
                        scopes: ["LEGAL_AID_APPLICATION"], budget_minutes: 20, from: T0)

    # Pinned before S2: S1 alone (25 <= 30) authorizes.
    d = decide(l, "SUPPORTER-B", "LEGAL_AID_APPLICATION", T1, as_of_seq: seq_one)
    assert d.authorized, d.reason_code
  end

  # --- Failed source + cumulative + cycle interplay -----------------------

  def test_invalid_source_denies_all_siblings_without_leaking_scope
    l = budgeted_source
    l.create_delegation(id: "DELEG-S1", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                        scopes: ["LEGAL_AID_APPLICATION"], budget_minutes: 10, from: T0)
    # Kill the source consent.
    l.revoke_consent(consent_id: "CONSENT-1", at: "2026-09-05T00:00:00Z")
    d = decide(l, "SUPPORTER-B", "LEGAL_AID_APPLICATION", "2026-09-20T00:00:00Z")
    refute d.authorized
    assert_equal R::SOURCE_CONSENT_INVALID, d.reason_code
    assert_scope_redacted(d.authority_chain)
  end

  def test_cumulative_cycle_still_detected
    # Sibling budgets on a cyclic sub-chain must not manufacture authority.
    l = budgeted_source
    l.create_delegation(id: "D-PQ", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-B", to_supporter_id: "SUPPORTER-C",
                        scopes: ["LEGAL_AID_APPLICATION"], budget_minutes: 5, from: T0)
    l.create_delegation(id: "D-QP", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-C", to_supporter_id: "SUPPORTER-B",
                        scopes: ["LEGAL_AID_APPLICATION"], budget_minutes: 5, from: T0)
    # Neither B nor C has a root consent for the scope (only A does), and they
    # only point at each other → cycle.
    d = decide(l, "SUPPORTER-C", "LEGAL_AID_APPLICATION", T1)
    refute d.authorized
    assert_equal R::DELEGATION_CYCLE, d.reason_code
    assert_scope_redacted(d.authority_chain)
  end

  # --- Concurrency: submit siblings + a revocation concurrently -----------

  def test_concurrent_sibling_submission_never_exceeds_source_budget
    # Two sibling sub-delegations (20 + 20) draw on a 30-minute source; one is
    # revoked. Fire the creations, the revocation, and the decisions
    # concurrently. Whatever the interleaving, the authorized siblings' budgets
    # (as-of each decision's own anchors) must never sum above the source, and
    # every recorded decision must replay identically at its own (time, seq).
    l = budgeted_source # budget = 30
    %w[SUPPORTER-D].each { |s| l.add_supporter(s) }
    l.create_delegation(id: "DELEG-S1", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-B",
                        scopes: ["LEGAL_AID_APPLICATION"], budget_minutes: 20, from: T0)
    l.create_delegation(id: "DELEG-S2", source_consent_id: "CONSENT-1",
                        from_supporter_id: "SUPPORTER-A", to_supporter_id: "SUPPORTER-C",
                        scopes: ["LEGAL_AID_APPLICATION"], budget_minutes: 20, from: T0)

    at = "2026-09-20T00:00:00Z"
    mutex = Mutex.new
    recorded = []
    threads = []

    threads << Thread.new { l.revoke_delegation(delegation_id: "DELEG-S1", at: "2026-09-10T00:00:00Z") }
    %w[SUPPORTER-B SUPPORTER-C].each do |sup|
      6.times do
        threads << Thread.new do
          d = l.decide(supporter_id: sup, scope: "LEGAL_AID_APPLICATION", at: at)
          mutex.synchronize { recorded << [sup, d.as_of_seq, d.reason_code, d.authorized] }
        end
      end
    end
    threads.each(&:join)

    recorded.each do |sup, seq, code, authorized|
      replay = l.evaluate(supporter_id: sup, scope: "LEGAL_AID_APPLICATION", at: at, as_of_seq: seq)
      assert_equal code, replay.reason_code, "#{sup}@seq#{seq} must replay identically"
      assert_equal authorized, replay.authorized

      # Invariant: at this decision's own anchors, the authorized siblings'
      # cumulative budget never exceeds the source's 30.
      total = authorized_sibling_budget(l, "CONSENT-1", at, seq)
      assert total <= 30, "cumulative authorized budget #{total} exceeded source at seq #{seq}"
    end

    # Final settled state: S1 revoked, S2 alone fits (20 <= 30).
    final = l.evaluate(supporter_id: "SUPPORTER-C", scope: "LEGAL_AID_APPLICATION", at: at)
    assert final.authorized
    b = l.evaluate(supporter_id: "SUPPORTER-B", scope: "LEGAL_AID_APPLICATION", at: at)
    assert_equal R::DELEGATION_REVOKED, b.reason_code
  end

  private

  # Sum of budgets over sibling sub-delegations that are authorized as-of the
  # given anchors (used to assert the shared-budget invariant in tests).
  def authorized_sibling_budget(ledger, source_consent_id, at, as_of_seq)
    proj = ledger.build_projection(as_of_seq: as_of_seq)
    engine = Consent::Engine.new(proj)
    proj.delegations.values.select do |d|
      d.source_consent_id == source_consent_id && d.budget_minutes
    end.sum do |d|
      dec = engine.evaluate(supporter_id: d.to_supporter_id,
                            scope: d.scopes.first, at: at)
      dec.authorized ? d.budget_minutes : 0
    end
  end

  def assert_scope_redacted(chain)
    refute_empty chain, "denied sub-chain must still carry structural evidence"
    chain.each do |link|
      refute link.key?("scopes"), "scopes must be redacted from denial evidence"
      refute link.key?("scope"), "scope must be redacted from denial evidence"
      assert_equal true, link["scopesRedacted"], "redaction must be flagged"
    end
  end
end
