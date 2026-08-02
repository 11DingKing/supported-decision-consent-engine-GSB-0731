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

## 7. Reason codes

Authorized: `AUTHORIZED`, `EMERGENCY_AUTHORIZED`.

Denials (highest priority first): `REVOKED`, `DELEGATION_SOURCE_REVOKED`,
`DELEGATION_BROADER_THAN_SOURCE`, `DELEGATION_CYCLE`, `EXPIRED`,
`DELEGATION_SOURCE_EXPIRED`, `DELEGATION_EXPIRED`, `NOT_YET_VALID`,
`DELEGATION_SOURCE_NOT_YET_VALID`, `DELEGATION_NOT_YET_VALID`, `WITNESS_MISSING`,
`SCOPE_NOT_GRANTED`, `DELEGATION_WITHOUT_SOURCE`, `EMERGENCY_TIMEOUT`,
`NO_CONSENT`.

The priority ordering guarantees a stable, meaningful code when multiple paths
fail: an explicit withdrawal always surfaces before a mere expiry, and an
attempt to broaden scope always surfaces before "no consent".

## 8. HTTP API

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

### Running

```bash
bundle install
bundle exec rake test                       # native test suite
SEED=materials/consent-cases.json bundle exec ruby app.rb
```
