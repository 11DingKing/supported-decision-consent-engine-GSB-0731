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

| code | meaning |
| --- | --- |
| `OK_DIRECT` | direct consent, active, in scope |
| `OK_DELEGATED` | delegation chain to an active direct consent |
| `OK_EMERGENCY` / `OK_EMERGENCY_REVIEW_PENDING` | inside emergency window (review recorded / not yet) |
| `DENY_NO_CONSENT` | nothing exists — silence is not consent |
| `DENY_SCOPE_NOT_COVERED` | consent exists but scope missing |
| `DENY_CONSENT_EXPIRED` / `DENY_CONSENT_REVOKED` | direct consent inactive |
| `DENY_DELEGATION_CYCLE` | chain loops without reaching a consent holder |
| `DENY_DELEGATION_SCOPE` | some link narrower than the requested scope |
| `DENY_DELEGATION_EXPIRED` | a delegation link past its `to` |
| `DENY_DELEGATION_SOURCE_EXPIRED` / `DENY_DELEGATION_SOURCE_REVOKED` | root consent inactive at decision time |
| `DENY_EMERGENCY_TIMEOUT` | past the emergency window |

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
- *In-flight decision at the exact revocation instant*: fail-closed, revoked
  wins. Evidence: `test_decision_at_exact_revocation_instant_is_revoked`,
  `test_one_second_before_revocation_instant_is_ok` (domain);
  `test_revoke_then_evaluate_and_double_revoke_conflict` (API).
- *History rewrite after revocation*: revocation is time-scoped; earlier
  decisions keep their verdict. Evidence: `test_replay_is_stable_after_history_grows`,
  `test_audit_events_are_immutable_at_database_level`.

**Delegation**
- *Broader-than-source delegation*: refused at write time (422) and denied
  again at evaluation even if persisted. Evidence:
  `test_validate_delegation_broader_than_source`,
  `test_broader_than_source_delegation_never_grants_even_if_persisted`,
  `test_broader_delegation_rejected_with_422`.
- *Multi-level / cycle chains*: chains resolve to the root consent; cycles
  terminate and deny. Evidence: `test_multi_level_delegation_chain`,
  `test_cycle_through_multiple_delegations_denies`,
  `test_write_time_cycle_detection`, `test_cycle_delegation_rejected_with_422`.
- *Source expiry/revocation after delegation*: delegated authority dies with
  its source, at write time and evaluation time. Evidence:
  `test_delegation_after_source_revocation_is_denied_at_evaluation`,
  `test_delegation_after_source_expiry_is_denied_at_evaluation`,
  `test_validate_delegation_after_source_expiry`,
  `test_delegation_after_source_revocation_rejected`.

**Emergency exception**
- *Timeout*: past `started_at + maxMinutes` the exception denies.
  Evidence: `test_emergency_timeout_denies`,
  `test_emergency_exactly_at_window_end_still_valid`,
  `test_emergency_flow_with_review_and_timeout`.
- *Scope creep / silent review*: only the policy scope qualifies; the review
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

## Native verification

```sh
bundle install
bundle exec rake test     # 44 runs, 286 assertions
bundle exec ruby app.rb   # serves on :4567, seeds materials/consent-cases.json
```

Docker is not required.
