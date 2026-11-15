# ADR 002: Refresh tokens live in Postgres, not Redis

- Status: PROPOSED (draft by assistant; rewrite in my own words before marking Accepted)
- Date: 2026-11-09
- Milestone: M1
- Changes: brief sections 4 and 10, which put refresh and fingerprint tokens in Redis.

## Context

Refresh tokens are rotated: each one is used once and replaced. If a token that was already
used shows up again, someone holds a copy, so the whole login chain must be revoked.
That needs three things from the store:

1. Know which tokens belong to the same login chain (a "family").
2. Revoke every session of one user (password change, admin action).
3. Keep sessions alive when infrastructure restarts.

Redis is also in the stack, so it was a candidate. The brief assumed it.

## Decision

Store refresh tokens in the Postgres table `refresh_tokens`:

- Only the SHA-256 hash of the token is stored, never the token. The tokens are 256-bit random
  values, so a fast hash is enough (unlike passwords, which use Argon2id).
- `family_id` groups the chain. `used_at` and `replaced_by` record rotation.
  `revoked_at` and `revoked_reason` record revocation.
- A token is claimed for rotation by one `UPDATE ... WHERE used_at IS NULL AND revoked_at IS NULL`.
  Only one of two simultaneous refreshes can match, so a race is treated as reuse.
- The lookup by token hash is the one query that is not tenant-scoped, because the client sends
  only the token. The row says which tenant it belongs to, and everything after the lookup is
  tenant-scoped again.
- Redis is not used for tokens. It stays for the rate limiter, Celery and caches.

## Alternatives considered

| Option | Why not |
|---|---|
| Redis only | Fast and has native expiry, but "revoke all of a user's sessions" and "revoke a family" need secondary indexes I would build by hand. A Redis restart without persistence logs everyone out. |
| Postgres source of truth plus Redis cache | More moving parts for a load I do not have. Can be added later without changing the table. |
| Stateless refresh JWT | Cannot be revoked and cannot detect reuse. |

## Consequences

Good:
- Reuse detection, per-family revocation and per-user revocation are single SQL statements.
- Sessions survive restarts of Redis and of the API.
- Every revocation is queryable and can be audited.

Costs:
- Every refresh is a database write, and each login adds a row.
- Expired rows pile up until a cleanup job deletes them. **That job does not exist yet**; it belongs
  with Celery beat in M2.
- A refresh needs Postgres to be awake. Supabase free projects pause when idle.

Known gaps:
- No grace period: a client that retries a refresh after a network drop looks like token reuse
  and is logged out. Real systems often allow a short window.
- Expiry is sliding: each rotation extends the session by the full TTL. An absolute maximum
  session age would be stricter.
- When the refresh endpoint rejects a request, the revocation it just wrote must still be
  committed. The API layer does this on purpose.

## Evidence

Tests in `tests/test_auth_flow.py`: rotation, reuse revokes the whole family, wrong fingerprint,
expired token, logout, logout-all, and another tenant cannot revoke a family.

## Revisit when

- Refresh traffic makes the extra writes a measured problem: add a Redis cache in front.
- Product needs an absolute session lifetime or a retry grace period.
