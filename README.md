# Supported Decision Consent Engine

Consent boundary API for supported decision-making. A supporter may only
assist with matters explicitly listed in a valid consent scope. Silence,
missing scope, expiry, or revocation never grant authority.

## Architecture

Authorization rules live **only** in pure Ruby domain objects. HTTP routes
and SQLite persistence orchestrate and store; they never judge.

- `lib/domain.rb` — pure domain: `Consent`, `Delegation`, `Revocation`,
  `EmergencyEpisode`, `World` (immutable fact snapshot at an audit seq),
  `Authorizer.evaluate` (pure verdict), `Validate` (write-time validation).
  No `require` of HTTP or DB code.
- `lib/store.rb` — append-only audit event log + immutable decision journal
  (SQLite). UPDATE/DELETE on both tables are blocked by triggers.
  `evaluate_and_record` pins `(event_time, as_of_seq)` inside one IMMEDIATE
  transaction so a verdict always references a consistent log prefix.
- `app.rb` — thin Sinatra routes: parse JSON, call `Domain::Validate` /
  `Store`, serialize results. Seeds an empty DB from
  `materials/consent-cases.json` (invalid facts like `DELEG-BROAD` are
  refused by domain validation, same as over the API).

## Boundary semantics (deterministic)

- Consent validity is half-open `[from, to)`: active at `from`, expired at `to`.
- Revocation wins ties: a decision exactly at the revocation instant is
  revoked (fail-closed). One second earlier is still authorized.
- Emergency window is inclusive: valid exactly at `started_at + maxMinutes`,
  timed out one second later.
- Denials use a fixed precedence list (`DENIAL_PRECEDENCE`), so competing
  denial reasons always resolve to the same stable reason code.

## Reason codes

| code                                                                | meaning                                             |
| ------------------------------------------------------------------- | --------------------------------------------------- |
| `OK_DIRECT`                                                         | direct consent, active, in scope                    |
| `OK_DELEGATED`                                                      | delegation chain to an active direct consent        |
| `OK_EMERGENCY` / `OK_EMERGENCY_REVIEW_PENDING`                      | inside emergency window (review recorded / not yet) |
| `DENY_NO_CONSENT`                                                   | nothing exists — silence is not consent             |
| `DENY_SCOPE_NOT_COVERED`                                            | consent exists but scope missing                    |
| `DENY_CONSENT_EXPIRED` / `DENY_CONSENT_REVOKED`                     | direct consent inactive                             |
| `DENY_DELEGATION_CYCLE`                                             | chain loops without reaching a consent holder       |
| `DENY_DELEGATION_SCOPE`                                             | some link narrower than the requested scope         |
| `DENY_DELEGATION_EXPIRED`                                           | a delegation link past its `to`                     |
| `DENY_DELEGATION_SOURCE_EXPIRED` / `DENY_DELEGATION_SOURCE_REVOKED` | root consent inactive at decision time              |
| `DENY_EMERGENCY_BUDGET_EXCEEDED`                                    | past the emergency budget granted along the chain   |
| `DENY_EMERGENCY_TIMEOUT`                                            | past the emergency window                           |

Write-time rejection codes (HTTP 422, journaled as `DELEGATION_REJECTED`
evidence events with scope-redacted chains): `DELEGATION_BROADER_THAN_SOURCE`,
`DELEGATION_CYCLE`, `DELEGATION_SOURCE_EXPIRED`, `DELEGATION_SOURCE_REVOKED`,
`DELEGATION_WINDOW_INVALID`, `DELEGATION_NOT_HELD_BY_SENDER`,
`DELEGATION_BUDGET_EXCEEDED`, `DELEGATION_BUDGET_INVALID`,
`CONSENT_BUDGET_EXCEEDS_POLICY`.

## Sub-delegation (round 2)

A sub-delegation may carry `emergencyBudgetMinutes` — a minutes allowance on
the person-level emergency policy. Three bounds are enforced at write time,
against the state visible at the commit-time audit seq:

- **scope** ⊆ what the sender effectively holds along the chain
- **duration** ≤ the tightest `valid_to` along the chain (never past the root)
- **emergency budget** ≤ source budget minus everything already allocated to
  sibling sub-delegations (cumulative per sender per source)

Validity is computed from **event time and audit sequence** together: source
liveness is judged at the sub-chain's `effectiveFrom` (event time), so a
late-arriving sub-chain recorded _after_ a revocation but effective _before_
it is still logged — and decisions split by event time (authorized up to the
revocation instant, denied after). Decisions pinned to an earlier seq never
see the late arrival. An attempt saved after its source was revoked in the
log is refused and its rejection is journaled as immutable evidence.

At evaluation, an emergency episode's usable minutes are capped by the live
budget-bearing authority of the supporter (minimum link along the best
chain); beyond the cap the verdict is `DENY_EMERGENCY_BUDGET_EXCEEDED`, and
beyond the policy window `DENY_EMERGENCY_TIMEOUT`. With no live budget
authority the policy alone applies.

Denial evidence (evaluation chains and `DELEGATION_REJECTED` payloads) keeps
reason codes, ids, statuses and `scopeCount`, but never scope contents.

## API

- `POST /persons` `{personId}`
- `POST /persons/:id/supporters` `{supporterId}`
- `POST /persons/:id/emergency-policy` `{allowedScope, maxMinutes, requiresReviewEvent}`
- `POST /persons/:id/consents` `{supporterId, scopes[], from, to, witnessId, id?}` → also journals `WITNESS_RECORDED`
- `POST /consents/:id/revoke` `{at?}` → 409 `ALREADY_REVOKED` on repeat
- `POST /consents/:id/delegations` `{toSupporterId, scopes[], at?, to?, fromSupporterId?}` → 422 with `DELEGATION_BROADER_THAN_SOURCE` / `DELEGATION_CYCLE` / `DELEGATION_SOURCE_EXPIRED` / `DELEGATION_SOURCE_REVOKED` / `DELEGATION_WINDOW_INVALID`
- `POST /persons/:id/emergencies` `{supporterId, scope, at?}` → 422 `EMERGENCY_SCOPE_NOT_ALLOWED` outside policy
- `POST /emergencies/:id/review` `{at?, reviewerId?}`
- `POST /decisions/evaluate` `{personId, supporterId, scope, at}` → `{decisionId, reasonCode, authorized, chain, asOfSeq, at}`
- `GET /decisions/:id` / `GET /decisions/:id/replay` → re-evaluates at the pinned `(at, asOfSeq)`; `replayMatches` must be true
- `GET /persons/:id/audit` → ordered immutable audit trail

## Threat cases and evidence

**Revocation**

- _In-flight decision at the exact revocation instant_: fail-closed, revoked
  wins. Evidence: `test_decision_at_exact_revocation_instant_is_revoked`,
  `test_one_second_before_revocation_instant_is_ok` (domain);
  `test_revoke_then_evaluate_and_double_revoke_conflict` (API).
- _History rewrite after revocation_: revocation is time-scoped; earlier
  decisions keep their verdict. Evidence: `test_replay_is_stable_after_history_grows`,
  `test_audit_events_are_immutable_at_database_level`.

**Delegation**

- _Broader-than-source delegation_: refused at write time (422) and denied
  again at evaluation even if persisted. Evidence:
  `test_validate_delegation_broader_than_source`,
  `test_broader_than_source_delegation_never_grants_even_if_persisted`,
  `test_broader_delegation_rejected_with_422`.
- _Multi-level / cycle chains_: chains resolve to the root consent; cycles
  terminate and deny. Evidence: `test_multi_level_delegation_chain`,
  `test_cycle_through_multiple_delegations_denies`,
  `test_write_time_cycle_detection`, `test_cycle_delegation_rejected_with_422`.
- _Source expiry/revocation after delegation_: delegated authority dies with
  its source, at write time and evaluation time. Evidence:
  `test_delegation_after_source_revocation_is_denied_at_evaluation`,
  `test_delegation_after_source_expiry_is_denied_at_evaluation`,
  `test_validate_delegation_after_source_expiry`,
  `test_delegation_after_source_revocation_rejected`.

**Emergency exception**

- _Timeout_: past `started_at + maxMinutes` the exception denies.
  Evidence: `test_emergency_timeout_denies`,
  `test_emergency_exactly_at_window_end_still_valid`,
  `test_emergency_flow_with_review_and_timeout`.
- _Scope creep / silent review_: only the policy scope qualifies; the review
  state is explicit (`OK_EMERGENCY_REVIEW_PENDING`) until a review event
  exists. Evidence: `test_emergency_never_covers_other_scopes`,
  `test_emergency_scope_outside_policy_rejected`.

**Races (concurrent grant vs. revoke)**

- Writers serialize in IMMEDIATE transactions; validation+append is atomic,
  so a consent is revoked at most once and no half-visible state exists.
  Every verdict pinned to `(at, asOfSeq)` replays identically, and no race
  authorizes a never-granted scope. Evidence:
  `test_concurrent_grants_revokes_and_evaluations` (16 decisions raced
  against 8 grants + 8 revocations: contiguous seq, exactly one revocation,
  all replays match, zero scope widening).

**Sub-delegation (round 2)**

- _Cumulative over-allocation_: two sibling sub-chains that each fit
  individually (20 + 20 > 30) are caught per sender per source, at every
  chain level. Evidence: `test_two_sibling_subchains_cumulative_over_allocation`,
  `test_multilevel_subchains_cumulative_over_allocation`,
  `test_cumulative_budget_over_allocation_over_http`.
- _Source revoked before the sub-chain is saved_: the attempt fails and its
  `DELEGATION_REJECTED` evidence is immutable and scope-redacted. Evidence:
  `test_revoke_before_subchain_save_leaves_redacted_evidence`,
  `test_rejected_subdelegation_leaves_scope_redacted_evidence`.
- _Late-arriving sub-chain_: validity splits by event time; decisions pinned
  to earlier audit seqs never see it. Evidence:
  `test_late_arriving_subchain_splits_by_event_time`,
  `test_late_arriving_subchain_by_event_time_and_audit_seq`,
  `test_late_arriving_subchain_validity_by_event_time_and_seq_over_http`.
- _Concurrent revoke vs. sub-chain saves_: no sub-holder is authorized past
  the revocation instant regardless of commit order; every failed attempt
  leaves redacted evidence; all verdicts replay. Evidence:
  `test_concurrent_revoke_vs_subchain_saves`.
- _Emergency budget drawn past the chain grant_: capped minutes enforced,
  multi-level minimum enforced, timeout still applies. Evidence:
  `test_emergency_beyond_delegated_budget_is_denied`,
  `test_emergency_budget_min_is_enforced_along_multilevel_chain`,
  `test_emergency_beyond_policy_window_still_times_out`.
- _Scope leakage through denial evidence_: denied chains carry `scopeCount`
  and statuses but never scope contents. Evidence:
  `test_denial_chain_redacts_scopes_but_keeps_structure`,
  `test_rejection_evidence_is_stable_and_redacted`.

## Native verification

```sh
bundle install
bundle exec rake test     # 71 runs, 436 assertions
bundle exec ruby app.rb   # serves on :4567, seeds materials/consent-cases.json
```

Docker is not required.
