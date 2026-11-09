"""Login rate limiting: the limiter itself (real Redis) and the /auth/login behaviour.

These tests need a reachable Redis (your Docker container). If Redis is down they are skipped,
not failed, so look for "skipped" in the pytest summary. Every test uses its own key prefix and
cleans up after itself.
"""

import asyncio
import uuid

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from nyaya.api.deps import Session, get_session
from nyaya.auth.passwords import hash_password
from nyaya.config import get_settings
from nyaya.main import create_app
from nyaya.ratelimit import RateLimiter, RateLimiterUnavailable, make_redis_client
from nyaya.repositories.users import UserRepository

PW = "correct horse battery staple"


# ---------- fixtures ----------

@pytest_asyncio.fixture
async def redis_client():
    client = make_redis_client(get_settings().redis_url.get_secret_value())
    try:
        await client.ping()
    except Exception:
        await client.aclose()
        pytest.skip("Redis is not reachable (start it with: docker compose --profile core up -d redis)")
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def make_limiter(redis_client):
    prefixes: list[str] = []

    def make(**overrides) -> RateLimiter:
        prefix = f"rltest:{uuid.uuid4().hex[:8]}"
        prefixes.append(prefix)
        params = {"ip_max": 100, "ip_window_s": 60, "account_max": 3, "account_window_s": 60,
                  "fail_open": True}
        params.update(overrides)
        return RateLimiter(redis_client, prefix=prefix, **params)

    yield make
    for prefix in prefixes:
        async for key in redis_client.scan_iter(match=f"{prefix}:*"):
            await redis_client.delete(key)


def dead_redis() -> aioredis.Redis:
    return make_redis_client("redis://127.0.0.1:1/0")  # nothing listens on port 1


# ---------- the limiter ----------

async def test_account_is_blocked_after_the_limit(make_limiter):
    limiter = make_limiter(account_max=3)
    for _ in range(3):
        assert (await limiter.login_attempt("1.1.1.1", "acme", "a@x.com")).allowed
    blocked = await limiter.login_attempt("1.1.1.1", "acme", "a@x.com")
    assert not blocked.allowed
    assert blocked.scope == "account"
    assert 1 <= blocked.retry_after <= 60


async def test_account_limit_applies_from_any_ip(make_limiter):
    limiter = make_limiter(account_max=2)
    assert (await limiter.login_attempt("1.1.1.1", "acme", "a@x.com")).allowed
    assert (await limiter.login_attempt("2.2.2.2", "acme", "a@x.com")).allowed
    blocked = await limiter.login_attempt("3.3.3.3", "acme", "a@x.com")
    assert not blocked.allowed and blocked.scope == "account"


async def test_ip_limit_applies_across_accounts(make_limiter):
    limiter = make_limiter(ip_max=2)
    assert (await limiter.login_attempt("9.9.9.9", "acme", "a@x.com")).allowed
    assert (await limiter.login_attempt("9.9.9.9", "acme", "b@x.com")).allowed
    blocked = await limiter.login_attempt("9.9.9.9", "acme", "c@x.com")
    assert not blocked.allowed and blocked.scope == "ip"


async def test_a_blocked_ip_does_not_burn_the_account_counter(make_limiter):
    limiter = make_limiter(ip_max=3, account_max=10)
    for _ in range(3):  # the attacker uses up their IP allowance (account counter: 3)
        assert (await limiter.login_attempt("6.6.6.6", "acme", "victim@x.com")).allowed
    for _ in range(5):  # then keeps hammering from the now-blocked IP
        blocked = await limiter.login_attempt("6.6.6.6", "acme", "victim@x.com")
        assert not blocked.allowed and blocked.scope == "ip"
    # If those 5 blocked attempts had been counted against the account, it would be at 8 and
    # the victim's 3 attempts below would hit the limit of 10. They must all go through.
    for _ in range(3):
        assert (await limiter.login_attempt("7.7.7.7", "acme", "victim@x.com")).allowed


async def test_accounts_and_tenants_are_isolated(make_limiter):
    limiter = make_limiter(account_max=1)
    assert (await limiter.login_attempt("1.1.1.1", "acme", "a@x.com")).allowed
    assert not (await limiter.login_attempt("1.1.1.1", "acme", "a@x.com")).allowed
    assert (await limiter.login_attempt("1.1.1.1", "acme", "b@x.com")).allowed  # other user
    assert (await limiter.login_attempt("1.1.1.1", "other", "a@x.com")).allowed  # other tenant


async def test_tenant_and_email_are_normalised(make_limiter):
    limiter = make_limiter(account_max=1)
    assert (await limiter.login_attempt("1.1.1.1", "Acme", "A@X.com ")).allowed
    assert not (await limiter.login_attempt("1.1.1.1", " acme", "a@x.com")).allowed


async def test_success_resets_the_account_counter(make_limiter):
    limiter = make_limiter(account_max=2)
    await limiter.login_attempt("1.1.1.1", "acme", "a@x.com")
    await limiter.login_attempt("1.1.1.1", "acme", "a@x.com")
    await limiter.login_succeeded("acme", "a@x.com")
    assert (await limiter.login_attempt("1.1.1.1", "acme", "a@x.com")).allowed
    assert (await limiter.login_attempt("1.1.1.1", "acme", "a@x.com")).allowed
    assert not (await limiter.login_attempt("1.1.1.1", "acme", "a@x.com")).allowed


async def test_the_window_expires(make_limiter):
    limiter = make_limiter(account_max=1, account_window_s=1)
    assert (await limiter.login_attempt("1.1.1.1", "acme", "a@x.com")).allowed
    assert not (await limiter.login_attempt("1.1.1.1", "acme", "a@x.com")).allowed
    await asyncio.sleep(1.5)
    assert (await limiter.login_attempt("1.1.1.1", "acme", "a@x.com")).allowed


async def test_every_counter_has_an_expiry(make_limiter, redis_client):
    limiter = make_limiter()
    await limiter.login_attempt("1.1.1.1", "acme", "a@x.com")
    keys = [k async for k in redis_client.scan_iter(match=f"{limiter.prefix}:*")]
    assert len(keys) == 2  # one for the IP, one for the account
    for key in keys:
        assert await redis_client.ttl(key) > 0  # a counter without expiry would block forever


async def test_redis_holds_no_email_addresses(make_limiter, redis_client):
    limiter = make_limiter()
    await limiter.login_attempt("1.1.1.1", "acme", "secret.person@example.com")
    async for key in redis_client.scan_iter(match=f"{limiter.prefix}:*"):
        assert "secret.person" not in key.decode()


async def test_fail_open_lets_logins_through_when_redis_is_down():
    limiter = RateLimiter(dead_redis(), ip_max=1, ip_window_s=60, account_max=1,
                          account_window_s=60, fail_open=True)
    assert (await limiter.login_attempt("1.1.1.1", "acme", "a@x.com")).allowed
    await limiter.login_succeeded("acme", "a@x.com")  # must not raise either


async def test_fail_closed_refuses_when_redis_is_down():
    limiter = RateLimiter(dead_redis(), ip_max=1, ip_window_s=60, account_max=1,
                          account_window_s=60, fail_open=False)
    with pytest.raises(RateLimiterUnavailable):
        await limiter.login_attempt("1.1.1.1", "acme", "a@x.com")


# ---------- /auth/login ----------

class _Session(Session):
    async def commit(self) -> None:  # the test transaction is rolled back at the end instead
        pass


@pytest_asyncio.fixture
async def build_client(conn, tenant_rows, two_tenants):
    (row_a, _), (ctx_a, _) = tenant_rows, two_tenants
    users = UserRepository(conn, ctx_a)
    await users.create("user@example.com", password_hash=hash_password(PW))
    clients: list[httpx.AsyncClient] = []

    async def build(limiter: RateLimiter) -> httpx.AsyncClient:
        app = create_app(readiness_checks={}, limiter=limiter)
        session = _Session(conn)

        async def override():
            return session

        app.dependency_overrides[get_session] = override
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=("203.0.113.7", 5000)),
            base_url="http://test",
        )
        client.slug = row_a["slug"]
        clients.append(client)
        return client

    yield build
    for client in clients:
        await client.aclose()


async def _login(client, email="user@example.com", password=PW):
    return await client.post(
        "/auth/login", json={"tenant": client.slug, "email": email, "password": password}
    )


async def test_login_is_locked_after_repeated_failures(build_client, make_limiter):
    client = await build_client(make_limiter(account_max=3))
    for _ in range(3):
        assert (await _login(client, password="wrong password here")).status_code == 401

    locked = await _login(client, password="wrong password here")
    assert locked.status_code == 429
    assert int(locked.headers["retry-after"]) >= 1

    # Even the CORRECT password is refused while the account is locked.
    assert (await _login(client)).status_code == 429


async def test_unknown_and_real_accounts_are_limited_identically(build_client, make_limiter):
    client = await build_client(make_limiter(account_max=3))
    real = [(await _login(client, "user@example.com", "wrong password here")).status_code
            for _ in range(4)]
    ghost = [(await _login(client, "nobody@example.com", "wrong password here")).status_code
             for _ in range(4)]
    assert real == ghost == [401, 401, 401, 429]  # no way to tell which accounts exist


async def test_a_successful_login_resets_the_failure_count(build_client, make_limiter):
    client = await build_client(make_limiter(account_max=3))
    for _ in range(2):
        assert (await _login(client, password="wrong password here")).status_code == 401
    assert (await _login(client)).status_code == 200
    for _ in range(2):  # would have been locked by now without the reset
        assert (await _login(client, password="wrong password here")).status_code == 401


async def test_ip_limit_blocks_login_spraying(build_client, make_limiter):
    client = await build_client(make_limiter(ip_max=2, account_max=50))
    assert (await _login(client, "a@example.com", "wrong password here")).status_code == 401
    assert (await _login(client, "b@example.com", "wrong password here")).status_code == 401
    assert (await _login(client, "c@example.com", "wrong password here")).status_code == 429


async def test_login_works_when_redis_is_down_and_limiter_fails_open(build_client):
    limiter = RateLimiter(dead_redis(), ip_max=5, ip_window_s=60, account_max=5,
                          account_window_s=60, fail_open=True)
    client = await build_client(limiter)
    assert (await _login(client)).status_code == 200


async def test_login_is_refused_when_redis_is_down_and_limiter_fails_closed(build_client):
    limiter = RateLimiter(dead_redis(), ip_max=5, ip_window_s=60, account_max=5,
                          account_window_s=60, fail_open=False)
    client = await build_client(limiter)
    assert (await _login(client)).status_code == 503
