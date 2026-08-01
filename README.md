# Supported Decision Consent Engine

Blank 0-1 baseline for evaluating consent boundaries in supported decision-making. It is not a role-permission administration system and includes no implementation.

## Source material

`materials/consent-cases.json` is authoritative for person, supporter, scope, decision, delegation, revocation, witness, and event-time identifiers.

## Required delivery contract

- Ruby with Sinatra and SQLite.
- Authorization rules live in pure Ruby domain objects rather than HTTP routes or persistence code.
- Silent, missing, expired, revoked, or broader-than-source consent never grants ordinary authority.
- Native verification: `bundle exec rake test` and `bundle exec ruby app.rb`.
- Final response documents revocation, delegation, and emergency threat cases with test evidence.

Docker is not required.

