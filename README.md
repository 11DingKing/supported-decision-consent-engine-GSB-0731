# Supported Decision Consent Engine

A consent-boundary API for supported decision-making. It manages the person,
their supporters, decision scopes, consents (with validity windows and
witnesses), delegations, revocations, an emergency exception, and an immutable
audit log. Every authority question is answered by a **pure Ruby domain
engine** that returns a stable `reasonCode` and a full `authorityChain`.

The engine's governing principle: **silence is never authority.** Missing,
unwitnessed, not-yet-effective, expired, revoked, or broader-than-source
consent all deny ordinary authority. The dangerous failure in this domain is
not an HTTP 500 — it is the system quietly treating silence as a "yes", or a
revocation racing an in-flight decision so a supporter's scope is silently
widened. This design closes those gaps by construction.

## Architecture

```
lib/consent/
  reason_codes.rb   # Stable reason-code vocabulary + fixed denial precedence
  instant.rb        # UTC time with explicit [from,to) window & revocation semantics
  canonical_json.rb # Deterministic serialization (hash chain + stable responses)
  event.rb          # Immutable recorded fact, SHA-256 hash-chained
  event_store.rb    # Append-only SQLite log; triggers forbid UPDATE/DELETE
  projection.rb     # Pure fold of events (up to an audit seq) into entities
  engine.rb         # THE authorization engine — pure, the only judge of authority
  ledger.rb         # Coordinator: records facts, pins decisions to (time, seq)
  seed.rb           # Loads the authoritative material as recorded facts
  api.rb            # Thin Sinatra adapter: parse -> domain -> serialize
app.rb              # Native entrypoint (boot, seed-if-empty, serve)
```

**Separation of concerns is enforced, not aspirational:**

- **HTTP (`api.rb`)** only parses JSON and serializes results. It contains no
  authorization logic and no time semantics.
- **Persistence (`event_store.rb`)** only appends and reads facts, assigns the
  monotonic audit `seq`, and maintains the hash chain. It never interprets
  whether a fact authorizes anything.
- **Domain (`engine.rb` + friends)** is the sole authority judge and is a pure
  function of `(recorded facts, event_time, as_of_seq)`.

## Determinism & replay

Every decision fixes two anchors:

- `eventTime` — the domain instant the decision is evaluated as-of.
- `asOfSeq` — the maximum audit sequence visible at that moment.

The projection hides any event with `seq > asOfSeq`, and denial selection uses
a **fixed precedence list**, never evaluation-time state. Therefore replaying a
decision with the same `(eventTime, asOfSeq)` always reproduces the identical
`reasonCode` and `authorityChain`. A later-appended (higher-seq) fact — e.g. a
concurrent revocation — can never rewrite a past decision or widen scope.

Boundary rules (chosen once, applied everywhere):

- Validity windows are half-open `[from, to)`: effective when `from <= t < to`.
- A revocation takes effect **at** its instant: `t >= revoked_at` ⇒ revoked,
  and revocation is checked **before** expiry. So a decision landing exactly on
  the revocation instant is deterministically denied.
- Revocation is monotonic: the earliest revocation wins and can never be loosened.

## API

| Method & path | Purpose |
|---|---|
| `GET  /health` | liveness + event count |
| `POST /persons` `/supporters` `/scopes` | register entities |
| `POST /consents` | grant consent (scopes, `from`, `to`, `witnessId`) |
| `POST /consents/:id/revocation` | revoke a consent at an instant |
| `POST /delegations` | delegate scope(s) from a source consent |
| `POST /delegations/:id/revocation` | revoke a delegation |
| `POST /emergency-policy` | set the emergency exception policy |
| `POST /emergencies` | invoke an emergency |
| `POST /emergencies/:id/review` | record a mandated review |
| `POST /decisions` | evaluate authority and **record** the decision |
| `POST /decisions/replay` | re-evaluate at fixed `(at, asOfSeq)` without recording |
| `GET  /events` | dump the immutable, hash-chained audit log |

A decision response:

```json
{
  "authorized": true,
  "reasonCode": "AUTHORIZED_DELEGATED_CONSENT",
  "supporterId": "SUPPORTER-B",
  "scope": "LEGAL_AID_APPLICATION",
  "eventTime": "2026-09-01T00:00:00Z",
  "asOfSeq": 11,
  "authorityChain": [
    {"type": "consent", "consentId": "CONSENT-1", "...": "..."},
    {"type": "delegation", "delegationId": "DELEG-OK", "...": "..."}
  ]
}
```

## Threat model & test evidence

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full mapping. Summary:

- **Revocation** — `test/revocation_test.rb`: exact-instant denial, monotonicity,
  precedence over expiry, replay before the revocation seq.
- **Delegation / re-delegation** — `test/delegation_test.rb`: multi-level chains,
  scope-exceeds-source, source expiry/revocation collapse, cycle detection.
- **Emergency** — `test/emergency_test.rb`: timeout hard-expiry, scope restriction,
  mandated-review-missing denial, non-delegatable, fallback-only ordering.
- **Races / history** — `test/determinism_test.rb`: replay stability, pinned
  decisions unaffected by later appends, concurrent grant+revoke never widens
  scope, unique monotonic seqs.
- **Immutability** — `test/event_store_test.rb`: UPDATE/DELETE forbidden, hash
  chain verified on load.

## Source material

`materials/consent-cases.json` is authoritative for person, supporter, scope,
decision, delegation, revocation, witness, and event-time identifiers. It is
loaded verbatim as recorded facts (`lib/consent/seed.rb`).

## Native verification

```sh
bundle install
bundle exec rake test        # full suite (domain, replay, concurrency, API, store)
bundle exec ruby app.rb      # boots on http://127.0.0.1:4567, seeds if empty
```

Docker is not required.
