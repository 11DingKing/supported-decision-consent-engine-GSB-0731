# Threat Model — Supported Decision Consent Engine

This document enumerates the ways a consent engine can *silently* over-grant
authority, states the defence built into the domain, and maps each to concrete
test evidence. Run the suite with `bundle exec rake test`.

The unifying invariant behind every defence:

> A decision is a pure function of `(recorded facts, eventTime, asOfSeq)`.
> Silence, absence, expiry, revocation, and scope-creep all deny ordinary
> authority. No race can widen scope or rewrite a recorded fact.

Reason codes are selected from a **fixed precedence list**
(`lib/consent/reason_codes.rb`, `DENIAL_PRECEDENCE`) so replays are stable and
a structural failure (a cycle) or an explicit withdrawal is never masked by a
vaguer "no consent" answer.

---

## 1. Revocation

**Threat.** The system keeps honouring a consent after the person withdrew it —
because the revocation was treated as taking effect "later", because an
in-flight decision landed exactly on the revocation instant and slipped
through, or because a natural expiry masked the real cause (revocation).

**Defence.**
- Revocation takes effect **at** its instant: `t >= revoked_at ⇒ revoked`
  (`Engine#consent_validity`, `Instant#at_or_after?`).
- Revocation is checked **before** expiry and before window/scope, so it is the
  reported, most-specific cause.
- Revocation is **monotonic**: the earliest revocation instant wins; a later
  event cannot loosen it (`Projection#apply` for `CONSENT_REVOKED`).
- Because decisions pin `asOfSeq`, a decision recorded before the revocation
  was appended replays to its original answer — history is not rewritten.

**Test evidence — `test/revocation_test.rb`**

| Test | Asserts |
|---|---|
| `test_just_before_revocation_still_authorized` | `09:59:59` → `AUTHORIZED_DIRECT_CONSENT` |
| `test_decision_at_exact_revocation_instant_is_revoked` | `10:00:00` → `CONSENT_REVOKED` (the in-flight edge case) |
| `test_after_revocation_is_revoked` | later → `CONSENT_REVOKED` |
| `test_revocation_takes_precedence_over_expiry` | revoked beats expired |
| `test_revocation_is_monotonic_cannot_be_loosened` | earliest revocation wins |
| `test_replay_before_revocation_seq_ignores_later_revocation` | pinning an earlier `asOfSeq` reproduces the pre-revocation grant |

---

## 2. Delegation & re-delegation (transfer of authority)

**Threat.** A supporter re-delegates authority they never held (scope creep);
delegated authority outlives the **source** consent's expiry or revocation; or
a delegation **cycle** manufactures authority from nothing (A→B→A).

**Defence.**
- Delegated authority is valid only if the **entire upstream chain** is
  independently valid as-of the same `eventTime` (`Engine#evaluate_delegation`
  recurses into `authority_for` for the source supporter).
- A delegation can never widen scope beyond its source: if the source never
  held the scope, the result is `DELEGATION_SCOPE_EXCEEDS_SOURCE`; if the source
  authority existed but is now expired/revoked, `SOURCE_CONSENT_INVALID`.
- Cycles are detected via a `visited` set on the resolution path and denied
  with `DELEGATION_CYCLE` (ranked highest in precedence).
- The returned `authorityChain` shows the full `consent → delegation → …` path
  for authorized decisions, so the granting basis is auditable.

**Test evidence — `test/delegation_test.rb`**

| Test | Asserts |
|---|---|
| `test_valid_delegation_authorizes_with_full_chain` | `AUTHORIZED_DELEGATED_CONSENT`, chain `[consent, delegation]` |
| `test_delegation_broader_than_source_denied` | `DELEGATION_SCOPE_EXCEEDS_SOURCE` (the `DELEG-BROAD` case: MEDICAL not in `CONSENT-1`) |
| `test_delegation_after_source_revoked_denied` | `SOURCE_CONSENT_INVALID` after `CONSENT-1` revoked |
| `test_delegation_after_source_expiry_denied` | delegation cannot outlive a dead source |
| `test_multi_level_delegation_chain` | A→B→C authorizes with `[consent, delegation, delegation]` |
| `test_multi_level_chain_breaks_when_root_revoked` | revoking the root collapses the whole chain |
| `test_delegation_cycle_denied` | `DELEGATION_CYCLE` for P→Q→P with no root |
| `test_expired_delegation_link_denied` | `DELEGATION_EXPIRED` for a lapsed link |

---

## 2a. Concurrent sub-delegation from one source authority (round 2)

**Threat.** Two supporters receive sub-delegations that draw on the **same
source consent**. Individually each looks fine, but together they let the
supporters wield more authority than the source ever held — via a wider scope,
a longer window, an oversized emergency budget, or two budgets that each fit
but **cumulatively** exceed the source. The race sharpens it: one
sub-delegation is revoked before its branch is persisted while another arrives
late, so a naive engine double-counts (or loses track of) the shared budget and
silently widens scope. A denial must also not leak *which* scopes the person
holds.

**Defence.** A sub-delegation may never grant more than its source. In addition
to scope containment (§2), three caps are checked as-of `(eventTime, asOfSeq)`
in `Engine#cap_violation`:

- **Duration** — a declared sub-window reaching outside the source's effective
  window (`Engine#duration_exceeds_source?`) →
  `DELEGATION_DURATION_EXCEEDS_SOURCE`. A `nil` bound inherits the source's,
  because the source authority is itself re-validated at `at`.
- **Per-link budget** — a delegated emergency-exception budget above the source
  consent's `emergencyBudgetMinutes` (or any budget when the source has none) →
  `DELEGATION_BUDGET_EXCEEDS_SOURCE`.
- **Cumulative sibling budget** — sub-delegations on the same source consent
  share ONE budget, summed greedily in `created_seq` order over the siblings
  **valid as-of `at`** (`Engine#cumulative_budget_exceeded?`). The sibling that
  pushes the running total over the source budget →
  `DELEGATION_BUDGET_EXCEEDED`.

The race resolves deterministically because validity is a pure function of the
anchors: a **revoked** sibling is not valid at `at`, so it frees its share; a
**late-arriving** sibling has a higher `seq`, so it is invisible to a decision
pinned below it and cannot retroactively consume budget. Every denied sub-chain
still returns authority-chain **evidence with scopes redacted**
(`Engine#redact`, `"scopesRedacted": true`), so an auditor sees *where* the
chain broke without learning the held scopes.

Reuses round-1 identifiers (`CONSENT-1`, `SUPPORTER-A/B/C`, `DELEG-OK`,
`DELEG-BROAD`, the three scopes, witness `W-1`) and the audit-seq ordering.

**Test evidence — `test/sub_delegation_test.rb`**

| Test | Asserts |
|---|---|
| `test_deleg_ok_still_authorizes_with_caps_in_place` | round-1 `DELEG-OK` still authorizes |
| `test_deleg_broad_denied_with_redacted_evidence` | `DELEGATION_SCOPE_EXCEEDS_SOURCE`, evidence scope-redacted |
| `test_sub_delegation_window_within_source_authorizes` | in-window sub authorizes |
| `test_sub_delegation_window_exceeds_source_denied` | `DELEGATION_DURATION_EXCEEDS_SOURCE` |
| `test_sub_delegation_budget_within_source_authorizes` | 20 ≤ 30 authorizes |
| `test_sub_delegation_budget_exceeds_source_denied` | `DELEGATION_BUDGET_EXCEEDS_SOURCE` (45 > 30) |
| `test_two_sub_chains_individually_fit_but_cumulatively_exceed` | 20+20 > 30 → second is `DELEGATION_BUDGET_EXCEEDED` |
| `test_revoked_sibling_frees_cumulative_budget` | revoke-before-save + delayed arrival: revoked sibling frees its budget |
| `test_before_revocation_seq_both_original_siblings_accounted` | pinned `asOfSeq` reproduces the historical cumulative answer |
| `test_delayed_sibling_not_visible_below_its_seq` | late sibling cannot retroactively consume budget |
| `test_invalid_source_denies_all_siblings_without_leaking_scope` | dead source → `SOURCE_CONSENT_INVALID`, redacted |
| `test_cumulative_cycle_still_detected` | budgets on a cyclic sub-chain still `DELEGATION_CYCLE` |
| `test_concurrent_sibling_submission_never_exceeds_source_budget` | concurrent creates+revoke+decisions: replay-stable, cumulative authorized budget never exceeds source |

Also verified over HTTP (`test/api_test.rb#test_sub_delegation_budget_cap_over_http_returns_redacted_evidence`) and against the live server: the cumulative overflow denies with redacted evidence, and revoking the first sibling re-authorizes the second.

---

## 3. Emergency exception

**Threat.** A time-boxed emergency override outlives its window (timeout
ignored); is used for a scope it was never meant for; skips a mandated review;
or is treated as delegatable and thereby laundered into ordinary authority.

**Defence.**
- Emergency is a **last-resort fallback**, considered only after ordinary
  authority fails (`Engine#evaluate` tries ordinary first).
- It hard-expires at `invoked_at + maxMinutes` (exclusive) →
  `EMERGENCY_EXPIRED`.
- It is scope-restricted to the policy's `allowedScope` →
  `EMERGENCY_SCOPE_NOT_ALLOWED`.
- When the policy requires review, a review event must be on record (as-of seq)
  or the exception is denied → `EMERGENCY_REVIEW_MISSING` (silence ≠ authority).
- Emergency grants never flow through delegation: a delegation's source path
  resolves only ordinary consent, so an emergency held by the source confers
  nothing downstream.

**Test evidence — `test/emergency_test.rb`**

| Test | Asserts |
|---|---|
| `test_emergency_authorizes_within_window_when_no_review_required` | `AUTHORIZED_EMERGENCY`, chain `[emergency]` |
| `test_emergency_expires_at_timeout_boundary` | at `+30min` → `EMERGENCY_EXPIRED` |
| `test_emergency_past_timeout_denied` | later → `EMERGENCY_EXPIRED` |
| `test_emergency_scope_restriction` | out-of-policy scope → `EMERGENCY_SCOPE_NOT_ALLOWED` |
| `test_required_review_missing_denies` | `EMERGENCY_REVIEW_MISSING` |
| `test_required_review_present_authorizes` | recorded review → authorized |
| `test_emergency_is_not_delegatable` | delegation from an emergency-holder confers nothing |
| `test_emergency_only_when_ordinary_authority_absent` | ordinary consent is preferred and reported |

---

## 4. Race conditions & history rewriting

**Threat.** A decision and a revocation (or a new grant) submitted concurrently
race such that authority is silently widened; or a later-recorded fact rewrites
the answer to a past decision.

**Defence.**
- Each decision pins `eventTime` **and** `asOfSeq` (the max audit seq visible at
  that moment). The projection hides `seq > asOfSeq`.
- Denial selection is a fixed precedence, not evaluation-time state.
- The event store serializes appends inside an `IMMEDIATE` transaction, so
  concurrent writers get distinct, ordered seqs and a single consistent chain.
- Therefore replaying `(eventTime, asOfSeq)` reproduces the identical reason
  code and authority chain; concurrency only affects the *order* facts are
  recorded, never a past decision's outcome.

**Test evidence — `test/determinism_test.rb`**

| Test | Asserts |
|---|---|
| `test_replay_is_deterministic_at_fixed_anchors` | 20 replays identical |
| `test_later_appended_fact_does_not_change_pinned_decision` | new revocation doesn't alter the pinned decision; current view does reflect it |
| `test_concurrent_grant_and_revoke_never_widens_scope` | every recorded decision replays identically at its own seq; final state is revoked |
| `test_concurrent_appends_produce_unique_ordered_seqs` | seqs unique & monotonic under threads |

---

## 5. Audit immutability (history is a fact, not an opinion)

**Threat.** History is quietly rewritten — a fact edited or deleted after the
event to change what a past decision "should" have seen.

**Defence.**
- The `events` table is append-only: `BEFORE UPDATE` and `BEFORE DELETE`
  triggers `RAISE(ABORT, …)` (`EventStore#migrate`).
- Every event is SHA-256 hash-chained to its predecessor; `load_events`
  re-derives and verifies the chain, raising `TamperError` on any break.
- Decisions themselves are recorded as `DECISION_REQUESTED` events, so the
  audit trail is a faithful, ordered record of what was asked and answered.

**Test evidence — `test/event_store_test.rb`**

| Test | Asserts |
|---|---|
| `test_append_assigns_monotonic_seq_and_chain` | seq monotonic, `prev_hash` links |
| `test_update_is_forbidden_by_trigger` | UPDATE raises "immutable" |
| `test_delete_is_forbidden_by_trigger` | DELETE raises "immutable" |
| `test_load_verifies_hash_chain` | chain verified on load |

Manually verified against the live server too: `UPDATE`/`DELETE` on the seeded
store both abort with `events are immutable`.

---

## Reason-code vocabulary

Authorized: `AUTHORIZED_DIRECT_CONSENT`, `AUTHORIZED_DELEGATED_CONSENT`,
`AUTHORIZED_EMERGENCY`.

Denied (most-specific first): `DELEGATION_CYCLE`, `CONSENT_REVOKED`,
`DELEGATION_REVOKED`, `SOURCE_CONSENT_INVALID`,
`DELEGATION_SCOPE_EXCEEDS_SOURCE`, `DELEGATION_DURATION_EXCEEDS_SOURCE`,
`DELEGATION_BUDGET_EXCEEDS_SOURCE`, `DELEGATION_BUDGET_EXCEEDED`,
`DELEGATION_SOURCE_AUTHORITY_MISSING`,
`CONSENT_EXPIRED`, `DELEGATION_EXPIRED`, `EMERGENCY_EXPIRED`,
`EMERGENCY_REVIEW_MISSING`, `EMERGENCY_SCOPE_NOT_ALLOWED`,
`CONSENT_NOT_WITNESSED`, `CONSENT_NOT_YET_EFFECTIVE`,
`DELEGATION_NOT_YET_EFFECTIVE`, `EMERGENCY_NOT_YET_EFFECTIVE`,
`SCOPE_NOT_IN_CONSENT`, `UNKNOWN_SUPPORTER`, `UNKNOWN_SCOPE`, `NO_CONSENT`.
