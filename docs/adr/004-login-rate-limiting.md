# ADR 004: Login rate limiting in Redis, per IP and per account

- Status: PROPOSED (draft by assistant; rewrite in my own words before marking Accepted)
- Date: 2026-11-09
- Milestone: M1

## Context

Argon2id makes each password check slow, but nothing stopped an attacker from guessing
passwords all day. Two attacks need different defences:

- One machine trying many accounts (spraying).
- Many machines trying one account (distributed guessing).

## Decision

Two fixed-window counters in Redis, checked before the password is verified:

| Limit | Default | Setting |
|---|---|---|
| Per IP address | 30 attempts per 300 s | `NYAYA_RATE_LIMIT_LOGIN_IP_MAX`, `..._WINDOW_S` |
| Per account (tenant + email) | 5 attempts per 900 s | `NYAYA_RATE_LIMIT_LOGIN_ACCOUNT_MAX`, `..._WINDOW_S` |

Over the limit the API answers `429` with a `Retry-After` header, even if the password is right.

Details that matter:
- The counter is incremented before the password check, using one atomic Lua script, so parallel
  guesses cannot slip under the limit.
- The IP is checked first. A blocked IP does not burn the account counter, so an attacker who is
  already blocked cannot lock a victim out.
- A successful login deletes the account counter.
- Account keys hold a SHA-256 of tenant plus email, so Redis stores no email addresses. Every
  counter has an expiry, and the script repairs a counter that lost its expiry.
- Unknown and real accounts follow the same sequence of responses (401, 401, 401, 429).
- If Redis is unreachable: fail open by default (`NYAYA_RATE_LIMIT_FAIL_OPEN=true`) so logins keep
  working; set it to false to refuse logins with 503 instead.
- The client address is `request.client.host`. Behind Nginx, run uvicorn with proxy-header
  support configured; never parse `X-Forwarded-For` in application code.

## Alternatives considered

| Option | Why not |
|---|---|
| Sliding window or token bucket | Avoids the burst at a window edge, but more code and state. Not needed yet. |
| In-process counters | Break when the API runs as several processes and reset on restart. |
| CAPTCHA or progressive delays | Good additions later; they need a frontend. |
| Rate limit in Nginx only | Cannot see the account, so it cannot do the per-account limit. Nginx can still add a coarse IP limit in M12. |

## Consequences

Good:
- Slows spraying and distributed guessing; failed attempts are also written to the audit log.
- Fast: two Redis round trips per login.

Costs and risks:
- **Account lockout is a denial of service:** anyone who knows an email can lock that account for
  up to 15 minutes. Accepted, with the IP limit slowing such an attacker.
- A fixed window allows a burst at the boundary, up to about twice the limit across two windows.
- Many users behind one office or NAT share one IP limit.
- Failing open means that during a Redis outage there is no brute-force protection. Decide
  deliberately for production.
- Only login is limited. Refresh and other endpoints are not.

## Evidence

`tests/test_ratelimit.py`: block at the limit, any-IP account limit, IP limit across accounts,
blocked IP does not burn the account counter, tenant and email isolation and normalisation,
reset on success, window expiry, every key has an expiry, no emails in Redis, fail open and fail
closed, and HTTP-level lockout.

## Revisit when

- Real traffic shows legitimate users being locked out.
- I add SSO (M12) or public endpoints that need their own limits.
- Production is planned: choose the fail-open setting and add the Nginx IP limit.
