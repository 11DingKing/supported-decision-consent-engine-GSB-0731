# Consent Boundary — Architecture & Threat Models

## 1. Layering (the hard rule)

Authorization judgment lives **only** in pure Ruby domain objects. HTTP routes and
the SQLite persistence layer never decide whether an action is allowed.

```
HTTP (Sinatra)          lib/consent_engine/api/server.rb
  │  - parse JSON, append events, render JSON
  │  - NO consent/scoping/revocation logic
  ▼
Persistence (SQLite)    lib/consent_engine/persistence/sqlite_event_store.rb
  │  - append-only event log with monotonic sequence
  │  - transactions for a consistent decision snapshot
  │  - NO authorization rules
  ▼
Domain (pure Ruby)      lib/consent_engine/domain/
     ConsentBoundary    - evaluates a request against an event prefix
     ReasonCode         - stable, prioritized outcome codes
     TimeWindow/ScopeSet- half-open [from,to) value objects
     ChainLink/Result   - complete authorization chain + audit
     EmergencyPolicy    - time-boxed exception policy
```

`ConsentBoundary.evaluate(events, request, policy)` takes a list of events (no
I/O, no database) and returns a `DecisionResult`. The exact same function is
used for live decisions and for replay verification.

## 2. Event-sourced audit trail

All state is derived from an immutable sequence of events:

| Event                    | Effect                                           |
|--------------------------|--------------------------------------------------|
| `ConsentGranted`         | Person grants a supporter a scoped, witnessed, time-bounded consent |
| `ConsentRevoked`         | Withdraws a consent at an instant                |
| `DelegationGranted`      | A supporter delegates a subset of a source consent |
| `DelegationRevoked`      | Withdraws a delegation                           |
| `EmergencyAccessStarted` | Begins a short emergency window for one scope    |
| `EmergencyReviewRecorded`| Post-hoc review of an emergency access           |
| `DecisionRecorded`       | An evaluated decision pins `seenSequence`, `reasonCode`, and `chain` |

Immutability is enforced at **two** layers:

1. The repository exposes only `append` — no update/delete methods.
2. SQLite triggers `events_no_update` / `events_no_delete` raise on any
   `UPDATE`/`DELETE`, so even a raw SQL connection cannot rewrite history.

## 3. Determinism and replay

Every `DecisionRecorded` event stores:

- `decisionAt` — the logical time of the decision,
- `seenSequence` — the highest event sequence visible when it was evaluated,
- `reasonCode` — the outcome code,
- `chain` — the complete authorization chain (person → consent → delegation...),
- `policySnapshot` — the emergency policy in force at the time.

Replaying events `1..seenSequence` through the same pure function reproduces the
**identical** reason code and chain. This is verified by
`GET /decisions/:id/verify` (and `SqliteEventStore#verify_replay`). A later
revocation never changes a historical decision, because the decision is pinned
to the event prefix it saw.

## 4. Boundary semantics (half-open intervals)

- Consent valid at `t` iff `validFrom <= t < validTo` and not revoked.
- Revocation is effective at its instant **inclusive**: `t >= revokedAt` ⇒ revoked.
- A delegation is valid only if it exists at `t` (`grantedAt <= t < validTo`),
  its source consent was active when the delegation was made, the source is
  still active at `t`, and its scopes are a **subset** of the source.
- Emergency window is `startedAt <= t < startedAt + maxMinutes`. The deadline
  instant itself is a timeout.

These are exact, testable boundaries — there is no "close enough".

## 5. Threat models and test evidence

### 5.1 Withdrawal (revocation)

**Threats**
- The system treats silence as ongoing consent after a person withdraws.
- An in-flight decision that lands at the revocation instant silently keeps
  authority ("just barely made it").
- A revocation does not cascade through delegations, leaving a delegate with
  authority the person already pulled.
- A later revocation rewrites a decision that was legitimately made earlier.

**Controls**
- `REVOKED` is the highest-priority denial reason.
- The exact revocation instant is denied (half-open: `t >= revokedAt`).
- Revocation cascades: a delegated chain whose root is revoked at `t` returns
  `DELEGATION_SOURCE_REVOKED`.
- A pre-revocation decision pins `seenSequence`; replay against that prefix
  still returns `AUTHORIZED` even after the revocation event is appended.

**Test evidence**
- `test_revocation_immediately_invalidates_consent` — one second before vs.
  exact instant vs. one second after.
- `test_revocation_cascades_to_delegation` — delegate denied after root revoke.
- `test_inflight_decision_at_exact_revocation_instant_is_deterministic` —
  decision made before the revoke stays `AUTHORIZED` on replay; a second
  decision at the same instant after seeing the revoke is `REVOKED`.
- `test_historical_decision_does_not_change_after_later_revocation` — replay
  of an old decision still matches despite later revocation.

### 5.2 Sub-delegation (transitive authority)

**Threats**
- A supporter delegates a scope they never held (privilege amplification).
- Multi-level chains quietly broaden scope at each hop.
- A delegation is backdated or made after the source consent expired.
- A circular delegation chain loops forever or launders authority.
- A delegation survives its own expiry or revocation.

**Controls**
- Every delegation's scopes must be a subset of its source consent's scopes
  (`DELEGATION_BROADER_THAN_SOURCE`); this is checked at each hop, so scope can
  only narrow, never widen.
- The source consent must have been active at the delegation's `grantedAt`
  (`DELEGATION_SOURCE_EXPIRED` / `DELEGATION_SOURCE_NOT_YET_VALID` /
  `DELEGATION_SOURCE_REVOKED`).
- A `visited` set detects supporter cycles (`DELEGATION_CYCLE`) and prevents
  infinite recursion.
- Each hop has its own validity window (`DELEGATION_EXPIRED`) and can be
  independently revoked (`REVOKED`).
- The complete chain is recorded, so every link is auditable.

**Test evidence**
- `test_delegation_broader_than_source_is_rejected` — `DELEG-BROAD` in the seed
  data (MEDICAL scope delegated from a LEGAL/HOUSING consent) is rejected.
- `test_multi_level_delegation_narrows_scope` — A→B→C chain is authorized with
  full chain `[C1, D1, D2]`.
- `test_delegation_chain_cycle_is_detected` — B→C→B loop returns
  `DELEGATION_CYCLE`.
- `test_delegation_after_source_expiry_is_invalid` — delegation made after the
  source consent's `validTo` is `DELEGATION_SOURCE_EXPIRED`.
- `test_delegation_without_source_consent` — orphan delegation.
- `test_expired_delegation` — delegation past its own `validTo`.
- `test_delegation_revocation_cuts_authority` — revoking a single hop cuts the
  downstream delegate.
- `test_race_cannot_expand_scope_via_delegation` — 10 concurrent broad
  delegations all produce `DELEGATION_BROADER_THAN_SOURCE`.

### 5.3 Emergency exception

**Threats**
- Emergency access is used as a standing backdoor (no time bound).
- The window leaks past its deadline, granting permanent authority.
- Emergency is invoked for scopes outside the single allowed scope.
- Emergency overrides denial for unrelated matters.

**Controls**
- Emergency is scoped to exactly one `allowedScope`; any other scope falls
  through to ordinary consent rules and cannot be authorized by emergency.
- The window closes at `startedAt + maxMinutes` (half-open); the deadline
  instant is `EMERGENCY_TIMEOUT`.
- Emergency grants `EMERGENCY_AUTHORIZED` only inside the window; it is recorded
  distinctly from ordinary `AUTHORIZED` so it is never mistaken for consent.
- A required review event is tracked on the result (`reviewRecorded`).

**Test evidence**
- `test_emergency_access_authorized_within_window` — inside 30 minutes.
- `test_emergency_access_times_out` — at deadline and one minute after are
  `EMERGENCY_TIMEOUT`.
- `test_emergency_scope_cannot_expand` — emergency for LEGAL cannot authorize
  MEDICAL.
- `test_emergency_does_not_override_other_scope_denial` — HOUSING with no
  consent remains `NO_CONSENT`.
- `test_emergency_review_recorded_is_reflected` — review flag is recorded.
- `test_emergency_timeout_is_race_safe` — boundary around the deadline is
  stable.

## 6. Concurrency model

- Writes are serialized by a mutex plus SQLite `BEGIN IMMEDIATE`, so event
  sequences are strictly monotonic with no gaps/duplicates.
- A decision reads a consistent snapshot (`max(sequence)`), evaluates against
  that prefix, and appends its own `DecisionRecorded` in the same transaction.
- Concurrent grant/revoke therefore produces a deterministic split: decisions
  whose `seenSequence` precedes the revoke are `AUTHORIZED`; decisions that see
  the revoke are `REVOKED`. There is no state that expands scope.

**Test evidence**
- `test_concurrent_grant_and_revocation_never_expands_scope` — 20 threads
  interleaving revoke and decision; every result is either `AUTHORIZED` or
  `REVOKED`, never an over-broad grant.
- `test_concurrent_appends_preserve_monotonic_sequences` — 50 concurrent appends
  yield exactly sequences 1..50 with no duplicates.

## 7. Round 2: sub-delegation boundaries

This round hardens transitive (sub-)delegation. It reuses the round-1
`CONSENT-1` / `SUPPORTER-A` / `SUPPORTER-B` identifiers, scopes, witness `W-1`,
and event sequences.

### 7.1 Bounds a sub-delegation must never exceed

A sub-delegation is valid only when all of the following hold against its
**source consent**:

1. **Scope** — every delegated scope is a subset of the source's scopes
   (`DELEGATION_BROADER_THAN_SOURCE`). This is checked at every hop, so a
   multi-level chain can only narrow.
2. **Duration** — the delegation's `validTo` is not later than the source's
   `validTo` (`DELEGATION_DURATION_EXCEEDS_SOURCE`). A delegate cannot outlive
   the authority that empowered them.
3. **Emergency budget (individual)** — if the delegation carries
   `emergencyBudgetMinutes`, it must not exceed the source's emergency budget
   (derived from policy: `maxMinutes` when the source covers the emergency
   scope) (`DELEGATION_BUDGET_EXCEEDED`).
4. **Emergency budget (cumulative)** — the sum of `emergencyBudgetMinutes`
   across all **active** (non-revoked, non-expired, in-window) sub-delegations
   from the same source must not exceed the source's budget
   (`DELEGATION_CUMULATIVE_BUDGET_EXCEEDED`). Revoked sub-delegations do not
   count. When over-committed, no sub-delegation can rely on emergency
   authority.
5. **Witness** — the source consent must carry a witness (`WITNESS_MISSING`).

### 7.2 Validity by event time AND audit sequence

A decision at time `t` with audit position `seenSequence` sees only events that
satisfy **both**:

- `sequence <= seenSequence` (audit order — events recorded after the decision
  are invisible), and
- `occurred_at <= t` (event time — future-dated events cannot affect a past
  decision).

This two-dimensional visibility prevents a late-appended event from rewriting
a past decision and prevents a future-dated grant from leaking backward.

Ordering violations on sub-delegations produce distinct codes:

- `DELEGATION_SOURCE_REVOKED` — the delegation was made (`grantedAt`) at or
  after the source revocation instant.
- `DELEGATION_LATE_ARRIVAL` — the delegation's `grantedAt` is before the
  revocation, but its **audit sequence** is after the revocation sequence
  (saved after the source was already withdrawn).
- `DELEGATION_SOURCE_EXPIRED` / `DELEGATION_SOURCE_NOT_YET_VALID` — the source
  was not active when the delegation was made.

### 7.3 Redacted chain evidence on denial

A rejected sub-delegation still returns a `chain` so auditors can see which
consent and which delegation link were evaluated. Denied links are **redacted**:

- `scopes` is `[]` and `redacted: true` is set,
- `witnessId` is omitted,
- but `id`, `kind`, `fromSubject`, `toSupporterId`, `sourceConsentId`, window,
  status, and `sequence` remain as evidence.

Reason codes never embed a scope name, so a denial cannot leak which scopes
exist beyond the structural IDs in the chain. The redaction is performed in the
domain layer (`build_consent_link`/`build_delegation_link` with `redacted:
true`), not in the HTTP layer.

### 7.4 Round-2 test evidence

All in [sub_delegation_boundary_test.rb](../test/sub_delegation_boundary_test.rb)
and [sub_delegation_concurrency_test.rb](../test/sub_delegation_concurrency_test.rb):

| Threat | Test | Reason code |
|--------|------|-------------|
| `DELEG-BROAD` grants MEDICAL from a LEGAL/HOUSING source | `test_deleg_broad_is_rejected_with_redacted_evidence` | `DELEGATION_BROADER_THAN_SOURCE` |
| Concurrent `DELEG-OK` + `DELEG-BROAD` evaluated independently | `test_concurrent_deleg_ok_and_deleg_broad_both_evaluated_independently` | `AUTHORIZED` / `DELEGATION_BROADER_THAN_SOURCE` |
| Delegation validTo past source validTo | `test_delegation_duration_exceeding_source_is_rejected` | `DELEGATION_DURATION_EXCEEDS_SOURCE` |
| Individual 60-min budget > 30-min source | `test_individual_emergency_budget_exceeding_source_is_rejected` | `DELEGATION_BUDGET_EXCEEDED` |
| Two 20-min sub-chains exceed 30-min source | `test_two_sub_chains_cumulative_emergency_budget_exceeded` | `DELEGATION_CUMULATIVE_BUDGET_EXCEEDED` |
| Two 15-min sub-chains within 30-min source | `test_cumulative_budget_within_limit_authorizes` | `AUTHORIZED` |
| Revoked sub-chain removed from cumulative sum | `test_revoked_sub_chain_does_not_count_toward_cumulative_budget` | `AUTHORIZED` |
| Source revoked before sub-chain saved (sequence ordering) | `test_source_revoked_before_sub_chain_saved_is_late_arrival` | `DELEGATION_LATE_ARRIVAL` |
| Delegation after source expiry | `test_delegation_after_source_expiry_is_source_expired` | `DELEGATION_SOURCE_EXPIRED` |
| Source revoked at decision time cascades | `test_source_revoked_at_decision_time_cascades` | `DELEGATION_SOURCE_REVOKED` |
| Circular sub-chain B→C→B | `test_circular_sub_chain_is_rejected_with_evidence` | `DELEGATION_CYCLE` |
| Future-dated event invisible to past decision | `test_event_time_filter_future_dated_event_does_not_affect_past_decision` | `NO_CONSENT` |
| Reason code stable across repeated evaluation | `test_reason_code_is_stable_across_repeated_evaluations` | stable |
| Rejected sub-chain replay matches | `test_rejected_sub_chain_replay_produces_identical_reason_and_chain` | reason + chain match |
| Chain evidence carries audit sequences | `test_chain_evidence_carries_audit_sequences` | sequences `[1,2]` |
| Witness requirement propagates to sub-chain | `test_witness_requirement_propagates_to_sub_chain` | `WITNESS_MISSING` |
| 8 concurrent 10-min delegations vs 30-min budget | `test_concurrent_sub_delegations_never_expand_budget` | at most 3 `AUTHORIZED`, rest `CUMULATIVE` |
| Concurrent grant+revoke then late delegation | `test_concurrent_grant_and_revoke_with_late_delegation` | `DELEGATION_LATE_ARRIVAL` |
| 6 concurrent broad delegations | `test_concurrent_broad_delegations_never_authorize` | `DELEGATION_BROADER_THAN_SOURCE` |

## 8. Round 3: revocation race, idempotency, and emergency budget

This round hardens the `REVOKE-1` race with in-flight decisions and closes the
remaining vectors for expanding scope or resetting budget through repeated
submission. It reuses round-1 event-time semantics and round-2 chains/budgets.

### 8.1 Microsecond revocation boundary

Time comparisons use `Time` with microsecond precision. The three boundary cases
are distinct and deterministic:

| Decision time relative to `revokedAt` | Result |
|----------------------------------------|--------|
| 1 µs before (`t < revokedAt`) | `AUTHORIZED` |
| exactly equal (`t == revokedAt`) | `REVOKED` |
| 1 µs after (`t > revokedAt`) | `REVOKED` |

The revocation instant is inclusive (`t >= revokedAt` ⇒ revoked). A decision
pinned one microsecond before the revoke remains `AUTHORIZED` on replay because
it was evaluated against the event prefix that did not yet contain the
revocation.

### 8.2 Out-of-order revocations

If two `ConsentRevoked` events target the same consent, the replay takes the
**earliest** `occurred_at` as the effective revocation time, regardless of
sequence order. A late-arriving revocation with an earlier timestamp cannot
rewrite a historical decision: that decision was pinned to the sequence prefix
it saw, and replay against that prefix reproduces the original outcome. A
duplicate revocation with the same `event_id` is idempotent (no new event row).

### 8.3 Decision idempotency

`POST /decisions` accepts an optional `decisionId` / `idempotencyKey`. When
provided:

- If a `DecisionRecorded` with that ID already exists, the stored result is
  returned unchanged with `idempotent: true` — no new event is appended and no
  budget is consumed.
- If the same key is reused with **different** decision parameters
  (person/supporter/scope/time), the request is rejected with `ArgumentError`
  to prevent a key from laundering a different authorization.
- A repeat submission therefore cannot expand scope, advance `seenSequence`, or
  reset emergency budget — it returns the exact original reason code, chain,
  and audit-sequence boundary.

The same idempotency applies to all event appends: a duplicate `event_id`
returns the existing event rather than inserting a second row.

### 8.4 Emergency budget consumption and revocation

Each `EmergencyAccessStarted` carries an optional `consumedMinutes`. The
domain layer sums consumed minutes across all prior emergency events for the
same scope (strictly earlier than the candidate) plus the candidate's own
consumption. If the total exceeds the policy `maxMinutes`, the result is
`EMERGENCY_BUDGET_EXHAUSTED`. The most recent emergency is the evaluation
candidate.

When a consent is revoked after an emergency has partially consumed budget:

- The consumed minutes remain recorded in the immutable event log.
- A decision within the emergency window still returns `EMERGENCY_AUTHORIZED`
  (emergency is the time-boxed exception), with `totalConsumedMinutes`
  reflecting the historical consumption.
- After the emergency window closes, the result is `EMERGENCY_TIMEOUT`.
- Repeated submission of the same emergency (`event_id`) does not double-count
  consumption; repeated submission of the same decision does not reset it.

### 8.5 Round-3 test evidence

All in [revocation_race_test.rb](../test/revocation_race_test.rb):

| Threat | Test | Expected reason |
|--------|------|-----------------|
| Decision 1µs before revoke | `test_decision_one_microsecond_before_revocation_is_authorized` | `AUTHORIZED` |
| Decision at exact revoke instant | `test_decision_at_exact_revocation_instant_is_revoked` | `REVOKED` |
| Decision 1µs after revoke | `test_decision_one_microsecond_after_revocation_is_revoked` | `REVOKED` |
| Three boundary results stable + idempotent replay | `test_three_boundary_results_are_stable_and_ordered` | mixed |
| In-flight decision pinned before revoke | `test_inflight_decision_pinned_before_revoke_stays_authorized_on_replay` | `AUTHORIZED` on replay |
| Earlier revocation arrives late | `test_earlier_revocation_arrives_later_effective_time_is_earliest` | `REVOKED` |
| Out-of-order revoke doesn't rewrite history | `test_out_of_order_revocation_does_not_rewrite_historical_decision` | replay matches |
| Duplicate revocation event idempotent | `test_duplicate_revocation_id_is_idempotent` | one event |
| Repeated decision with same key | `test_repeated_decision_with_same_idempotency_key_returns_same_result` | `idempotent: true` |
| Idempotent replay after revoke stays authorized | `test_idempotent_replay_after_revocation_preserves_original_authorization` | `AUTHORIZED` |
| Same key, different scope rejected | `test_repeated_submission_cannot_expand_scope` | `ArgumentError` |
| Emergency partial use then revoke | `test_emergency_partial_use_then_revoke_consumed_budget_preserved` | `EMERGENCY_AUTHORIZED`, budget preserved |
| Duplicate emergency doesn't double-consume | `test_repeated_emergency_submission_does_not_double_consume_budget` | consumed = 10 |
| Cumulative emergency budget exceeded | `test_cumulative_emergency_budget_cannot_exceed_source` | `EMERGENCY_BUDGET_EXHAUSTED` |
| Emergency budget replay deterministic | `test_emergency_budget_replay_is_deterministic_after_revoke` | replay matches |
| Repeated decision cannot reset budget | `test_repeated_submission_cannot_reset_emergency_budget` | consumed unchanged |
| Concurrent revoke + in-flight decisions | `test_concurrent_revoke_and_inflight_decisions_never_expand_scope` | no over-broad grant |
| 10 concurrent idempotent decisions | `test_concurrent_idempotent_decisions_produce_single_event` | exactly one event |

## 9. Reason codes

Authorized: `AUTHORIZED`, `EMERGENCY_AUTHORIZED`.

Denials (highest priority first): `REVOKED`, `DELEGATION_SOURCE_REVOKED`,
`DELEGATION_LATE_ARRIVAL`, `DELEGATION_BROADER_THAN_SOURCE`,
`DELEGATION_DURATION_EXCEEDS_SOURCE`, `DELEGATION_BUDGET_EXCEEDED`,
`DELEGATION_CUMULATIVE_BUDGET_EXCEEDED`, `EMERGENCY_BUDGET_EXHAUSTED`,
`DELEGATION_CYCLE`, `EXPIRED`,
`DELEGATION_SOURCE_EXPIRED`, `DELEGATION_EXPIRED`, `NOT_YET_VALID`,
`DELEGATION_SOURCE_NOT_YET_VALID`, `DELEGATION_NOT_YET_VALID`, `WITNESS_MISSING`,
`SCOPE_NOT_GRANTED`, `DELEGATION_WITHOUT_SOURCE`, `EMERGENCY_TIMEOUT`,
`NO_CONSENT`.

The priority ordering guarantees a stable, meaningful code when multiple paths
fail: an explicit withdrawal always surfaces before a mere expiry, and an
attempt to broaden scope always surfaces before "no consent".

## 10. HTTP API

| Method | Path                                           | Purpose |
|--------|------------------------------------------------|---------|
| GET    | `/health`                                      | liveness |
| POST   | `/people/:person_id/consents`                  | grant consent |
| POST   | `/consents/:consent_id/revocations`            | revoke consent |
| POST   | `/consents/:consent_id/delegations`            | create delegation |
| POST   | `/delegations/:delegation_id/revocations`      | revoke delegation |
| POST   | `/emergencies`                                 | start emergency window |
| POST   | `/emergencies/:id/review`                      | record emergency review |
| POST   | `/decisions`                                   | evaluate (pins sequence + chain) |
| GET    | `/decisions/:id`                               | fetch recorded decision |
| GET    | `/decisions/:id/verify`                        | replay and compare |
| GET    | `/events`                                      | list audit events |
| GET    | `/events/:sequence`                            | fetch a single event |

Delegation creation accepts an optional `emergencyBudgetMinutes` (integer). The
domain layer enforces individual and cumulative bounds against the source
consent's emergency budget. Denied decisions return a redacted `chain` with
`sequence` on each link for audit traceability.

`POST /decisions` accepts an optional `decisionId`/`idempotencyKey`; repeating
a request with the same key returns the original result (`idempotent: true`)
without appending a new event or consuming budget. `POST /emergencies` accepts
optional `sourceConsentId` and `consumedMinutes` (integer) to record emergency
budget consumption. All event-creating endpoints are idempotent on `id`/`event_id`.

### Running

```bash
bundle install
bundle exec rake test                       # native test suite
SEED=materials/consent-cases.json bundle exec ruby app.rb
```
