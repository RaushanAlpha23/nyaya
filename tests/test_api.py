"""HTTP-level tests: cookies, CSRF, rotation, reuse, readiness.

The app's database session is replaced by the test's rolled-back connection, so nothing is left
in the database. The replacement counts commits, which lets us prove that failed refreshes are
still committed (otherwise reuse detection would silently be undone in production).
"""

import httpx
import pytest
import pytest_asyncio

from nyaya.api.cookies import CSRF_COOKIE, FINGERPRINT_COOKIE, REFRESH_COOKIE
from nyaya.api.deps import Session, get_session
from nyaya.auth.passwords import hash_password
from nyaya.main import create_app
from nyaya.repositories.users import UserRepository

PW = "correct horse battery staple"


class RecordingSession(Session):
    def __init__(self, conn) -> None:
        super().__init__(conn)
        self.commits = 0

    async def commit(self) -> None:
        self.commits += 1  # the test transaction is rolled back at the end instead


async def _ok() -> None:
    return None


async def _boom() -> None:
    raise ConnectionError("secret-host.example.com refused the connection")


@pytest_asyncio.fixture
async def api(conn, tenant_rows, two_tenants):
    (row_a, _), (ctx_a, _) = tenant_rows, two_tenants
    users = UserRepository(conn, ctx_a)
    user = await users.create("user@example.com", password_hash=hash_password(PW))
    await users.assign_role(user["id"], "approver")

    app = create_app(readiness_checks={"postgres": _ok, "redis": _ok})
    session = RecordingSession(conn)

    async def override():
        return session

    app.dependency_overrides[get_session] = override

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        client.slug, client.session, client.app, client.user = row_a["slug"], session, app, user
        client.tenant_id = ctx_a.tenant_id
        yield client


async def _login(client, password=PW):
    return await client.post(
        "/auth/login",
        json={"tenant": client.slug, "email": "user@example.com", "password": password},
    )


def _csrf(client):
    return {"X-CSRF-Token": client.cookies.get(CSRF_COOKIE)}


# ---------- ops ----------

async def test_health(api):
    r = await api.get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    assert r.headers["x-request-id"]


async def test_ready_ok(api):
    r = await api.get("/ready")
    assert r.status_code == 200
    assert r.json() == {"status": "ready", "checks": {"postgres": "ok", "redis": "ok"}}


async def test_ready_names_the_failing_store_without_leaking_details(api):
    api.app.state.readiness_checks = {"postgres": _ok, "redis": _boom}
    r = await api.get("/ready")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "not_ready"
    assert body["checks"] == {"postgres": "ok", "redis": "fail: ConnectionError"}
    assert "secret-host" not in r.text


# ---------- login ----------

async def test_login_returns_token_and_sets_cookies(api):
    r = await _login(api)
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer" and body["access_token"]
    assert body["tenant_id"] == str(api.tenant_id)

    cookies = {c.split("=", 1)[0]: c.lower() for c in r.headers.get_list("set-cookie")}
    assert "httponly" in cookies[REFRESH_COOKIE] and "path=/auth" in cookies[REFRESH_COOKIE]
    assert "httponly" in cookies[FINGERPRINT_COOKIE]
    assert "httponly" not in cookies[CSRF_COOKIE]
    assert all("samesite=strict" in c for c in cookies.values())
    assert api.session.commits >= 1


async def test_bad_login_is_401_sets_no_cookies_and_commits_the_audit_entry(api):
    before = api.session.commits
    r = await _login(api, password="wrong password entirely")
    assert r.status_code == 401
    assert r.json() == {"detail": "invalid credentials"}
    assert not r.headers.get_list("set-cookie")
    assert api.session.commits == before + 1


# ---------- access token ----------

async def test_me_requires_bearer_token_and_fingerprint_cookie(api):
    token = (await _login(api)).json()["access_token"]

    ok = await api.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert ok.status_code == 200
    assert ok.json()["roles"] == ["approver"]
    assert ok.json()["tenant_id"] == str(api.tenant_id)

    assert (await api.get("/auth/me")).status_code == 401

    # A stolen token without the fingerprint cookie is useless.
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://test"
    ) as thief:
        r = await thief.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


# ---------- refresh ----------

async def test_refresh_rotates_cookies_and_returns_new_access_token(api):
    first = (await _login(api)).json()
    old_refresh = api.cookies.get(REFRESH_COOKIE)

    r = await api.post("/auth/refresh", headers=_csrf(api))

    assert r.status_code == 200
    assert r.json()["access_token"] != first["access_token"]
    assert api.cookies.get(REFRESH_COOKIE) != old_refresh


async def test_refresh_requires_a_matching_csrf_header_and_does_not_consume_the_token(api):
    await _login(api)

    assert (await api.post("/auth/refresh")).status_code == 403
    wrong = await api.post("/auth/refresh", headers={"X-CSRF-Token": "not-the-cookie-value"})
    assert wrong.status_code == 403

    assert (await api.post("/auth/refresh", headers=_csrf(api))).status_code == 200


async def test_refresh_without_cookies_is_401(api):
    api.cookies.set(CSRF_COOKIE, "x", path="/")
    r = await api.post("/auth/refresh", headers={"X-CSRF-Token": "x"})
    assert r.status_code == 401


async def test_reused_refresh_token_is_401_clears_cookies_and_commits_the_revocation(api):
    await _login(api)
    old_refresh, old_fp = api.cookies.get(REFRESH_COOKIE), api.cookies.get(FINGERPRINT_COOKIE)
    assert (await api.post("/auth/refresh", headers=_csrf(api))).status_code == 200
    newest_refresh = api.cookies.get(REFRESH_COOKIE)

    # The attacker replays the OLD cookies.
    api.cookies.set(REFRESH_COOKIE, old_refresh, path="/auth")
    api.cookies.set(FINGERPRINT_COOKIE, old_fp, path="/")
    before = api.session.commits
    r = await api.post("/auth/refresh", headers=_csrf(api))

    assert r.status_code == 401
    assert api.session.commits == before + 1, "revocation must be committed even on failure"
    assert any(c.lower().startswith(f"{REFRESH_COOKIE}=") for c in r.headers.get_list("set-cookie"))

    # The family is dead, so the real user's newest token no longer works either.
    api.cookies.set(REFRESH_COOKIE, newest_refresh, path="/auth")
    api.cookies.set(CSRF_COOKIE, "csrf", path="/")
    again = await api.post("/auth/refresh", headers={"X-CSRF-Token": "csrf"})
    assert again.status_code == 401


# ---------- logout ----------

async def test_logout_clears_cookies_and_revokes_the_session(api):
    await _login(api)
    refresh_cookie, fp_cookie = api.cookies.get(REFRESH_COOKIE), api.cookies.get(FINGERPRINT_COOKIE)

    r = await api.post("/auth/logout", headers=_csrf(api))
    assert r.status_code == 204
    assert api.cookies.get(REFRESH_COOKIE) is None

    api.cookies.set(REFRESH_COOKIE, refresh_cookie, path="/auth")
    api.cookies.set(FINGERPRINT_COOKIE, fp_cookie, path="/")
    api.cookies.set(CSRF_COOKIE, "csrf", path="/")
    assert (await api.post("/auth/refresh", headers={"X-CSRF-Token": "csrf"})).status_code == 401


async def test_logout_requires_csrf(api):
    await _login(api)
    assert (await api.post("/auth/logout")).status_code == 403
