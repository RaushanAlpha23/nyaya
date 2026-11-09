"""Login rate limiting with Redis.

Two independent limits, both fixed windows (a counter that expires):
- per IP address:        stops one machine from trying many accounts.
- per account (tenant + email): stops guessing one account from many machines.

Design notes:
- The counter is incremented BEFORE the password is checked. That makes the gate race-safe:
  50 parallel guesses cannot all slip under the limit, because INCR is atomic.
- A successful login deletes the account counter, so normal users who mistype are not punished.
- The IP is checked first. A blocked IP does not burn the account counter, so an attacker who
  is already blocked cannot lock a victim's account out.
- Account keys use a hash of tenant + email, so Redis holds no email addresses.
- Known trade-off: an attacker can deliberately lock a known account for one window.
  Accepted here; the window is short and the IP limit slows the attacker down.
- If Redis is unreachable: fail open (let the login proceed) or fail closed (refuse it),
  chosen by settings. Failing open keeps the product usable; failing closed is stricter.
"""

import hashlib
import logging
from dataclasses import dataclass

import redis.asyncio as aioredis
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff
from redis.exceptions import RedisError

from nyaya.config import get_settings

log = logging.getLogger(__name__)

# INCR, set the expiry on the first hit (and repair a key that lost its expiry), return the
# new count and the seconds left. One round trip, atomic.
_HIT_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
local ttl = redis.call('TTL', KEYS[1])
if count == 1 or ttl < 0 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
    ttl = tonumber(ARGV[1])
end
return {count, ttl}
"""


class RateLimiterUnavailable(Exception):
    """Redis is unreachable and the limiter is configured to fail closed."""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    retry_after: int = 0  # seconds until the window resets
    scope: str | None = None  # "ip" or "account" when blocked


def make_redis_client(url: str) -> aioredis.Redis:
    # No retries: during a Redis outage a login should fail fast, not hang for seconds.
    return aioredis.Redis.from_url(
        url, socket_timeout=2, socket_connect_timeout=2, retry=Retry(NoBackoff(), 0)
    )


class RateLimiter:
    def __init__(
        self,
        redis: aioredis.Redis,
        *,
        ip_max: int,
        ip_window_s: int,
        account_max: int,
        account_window_s: int,
        fail_open: bool = True,
        prefix: str = "rl:login",
    ) -> None:
        self._redis = redis
        self._script = redis.register_script(_HIT_SCRIPT)
        self.ip_max, self.ip_window_s = ip_max, ip_window_s
        self.account_max, self.account_window_s = account_max, account_window_s
        self.fail_open = fail_open
        self.prefix = prefix

    @classmethod
    def from_settings(cls, redis: aioredis.Redis) -> "RateLimiter":
        s = get_settings()
        return cls(
            redis,
            ip_max=s.rate_limit_login_ip_max,
            ip_window_s=s.rate_limit_login_ip_window_s,
            account_max=s.rate_limit_login_account_max,
            account_window_s=s.rate_limit_login_account_window_s,
            fail_open=s.rate_limit_fail_open,
        )

    def _ip_key(self, ip: str) -> str:
        return f"{self.prefix}:ip:{ip}"

    def _account_key(self, tenant: str, email: str) -> str:
        identity = f"{tenant.strip().lower()}\x00{email.strip().lower()}"
        return f"{self.prefix}:acct:{hashlib.sha256(identity.encode()).hexdigest()[:32]}"

    async def _hit(self, key: str, window_s: int) -> tuple[int, int]:
        count, ttl = await self._script(keys=[key], args=[window_s])
        return int(count), int(ttl)

    async def login_attempt(self, ip: str, tenant: str, email: str) -> Decision:
        """Call before checking the password. Counts this attempt."""
        try:
            count, ttl = await self._hit(self._ip_key(ip), self.ip_window_s)
            if count > self.ip_max:
                return Decision(False, max(ttl, 1), "ip")
            count, ttl = await self._hit(self._account_key(tenant, email), self.account_window_s)
            if count > self.account_max:
                return Decision(False, max(ttl, 1), "account")
            return Decision(True)
        except (RedisError, OSError) as e:
            log.warning("rate limiter unavailable (%s)", type(e).__name__)
            if self.fail_open:
                return Decision(True)
            raise RateLimiterUnavailable from e

    async def login_succeeded(self, tenant: str, email: str) -> None:
        """Forget earlier failures for this account. Never blocks a successful login."""
        try:
            await self._redis.delete(self._account_key(tenant, email))
        except (RedisError, OSError) as e:
            log.warning("could not reset login counter (%s)", type(e).__name__)
