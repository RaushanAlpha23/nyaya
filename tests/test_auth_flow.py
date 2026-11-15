"""Login, refresh rotation and reuse detection against the real database."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from argon2 import PasswordHasher
from sqlalchemy import text

from nyaya.auth import service
from nyaya.auth.passwords import hash_password
from nyaya.auth.service import AuthError, ReuseDetected
from nyaya.auth.tokens import decode_access_token, hash_token
from nyaya.repositories.audit import AuditRepository
from nyaya.repositories.refresh_tokens import RefreshTokenRepository, find_refresh_token
from nyaya.repositories.users import UserRepository

PW = "correct horse battery staple"


async def make_user(
    conn, ctx, email="user@example.com", password=PW, roles=("viewer",), hashed=None
):
    users = UserRepository(conn, ctx)
    user = await users.create(email, password_hash=hashed or hash_password(password))
    for role in roles:
        await users.assign_role(user["id"], role)
    return user


async def token_row(conn, refresh_token):
    return await find_refresh_token(conn, hash_token(refresh_token))


# ---------- login ----------

async def test_login_success_returns_usable_tokens(conn, tenant_rows, two_tenants):
    (row_a, _), (ctx_a, _) = tenant_rows, two_tenants
    user = await make_user(conn, ctx_a, roles=("approver", "viewer"))

    pair = await service.login(conn, row_a["slug"], "User@Example.com", PW)

    claims = decode_access_token(pair.access_token, pair.fingerprint)
    assert claims.user_id == user["id"]
    assert claims.tenant_id == ctx_a.tenant_id
    assert claims.roles == ("approver", "viewer")


async def test_only_the_hash_of_the_refresh_token_is_stored(conn, tenant_rows, two_tenants):
    (row_a, _), (ctx_a, _) = tenant_rows, two_tenants
    await make_user(conn, ctx_a)
    pair = await service.login(conn, row_a["slug"], "user@example.com", PW)

    row = await token_row(conn, pair.refresh_token)
    assert row is not None
    assert bytes(row["token_hash"]) == hash_token(pair.refresh_token)
    assert pair.refresh_token.encode() not in bytes(row["token_hash"])


async def test_bad_credentials_all_fail_with_the_same_message(conn, tenant_rows, two_tenants):
    (row_a, _), (ctx_a, _) = tenant_rows, two_tenants
    await make_user(conn, ctx_a)

    messages = set()
    for slug, email, password in [
        (row_a["slug"], "user@example.com", "wrong password entirely"),
        (row_a["slug"], "nobody@example.com", PW),
        ("no-such-tenant", "user@example.com", PW),
    ]:
        with pytest.raises(AuthError) as exc:
            await service.login(conn, slug, email, password)
        messages.add(str(exc.value))
    assert messages == {"invalid credentials"}


async def test_same_email_in_two_tenants_logs_into_the_right_one(conn, tenant_rows, two_tenants):
    (row_a, _), (ctx_a, ctx_b) = tenant_rows, two_tenants
    await make_user(conn, ctx_a, password="password for tenant A!!")
    await make_user(conn, ctx_b, password="password for tenant B!!")

    pair_a = await service.login(conn, row_a["slug"], "user@example.com", "password for tenant A!!")
    assert pair_a.tenant_id == ctx_a.tenant_id

    # Tenant B's password must not work at tenant A's login.
    with pytest.raises(AuthError):
        await service.login(conn, row_a["slug"], "user@example.com", "password for tenant B!!")


async def test_inactive_user_and_suspended_tenant_cannot_login(conn, tenant_rows, two_tenants):
    (row_a, row_b), (ctx_a, ctx_b) = tenant_rows, two_tenants
    user_a = await make_user(conn, ctx_a)
    await make_user(conn, ctx_b)

    await conn.execute(
        text("update users set is_active = false where id = :id"), {"id": user_a["id"]}
    )
    with pytest.raises(AuthError):
        await service.login(conn, row_a["slug"], "user@example.com", PW)

    await conn.execute(
        text("update tenants set status = 'suspended' where id = :id"), {"id": row_b["id"]}
    )
    with pytest.raises(AuthError):
        await service.login(conn, row_b["slug"], "user@example.com", PW)


async def test_login_upgrades_a_weak_hash(conn, tenant_rows, two_tenants):
    (row_a, _), (ctx_a, _) = tenant_rows, two_tenants
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(PW)
    user = await make_user(conn, ctx_a, hashed=weak)

    await service.login(conn, row_a["slug"], "user@example.com", PW)

    stored = (await conn.execute(
        text("select password_hash from users where id = :id"), {"id": user["id"]}
    )).scalar_one()
    assert stored != weak
    assert stored.startswith("$argon2id$")


async def test_login_and_failed_login_are_audited(conn, tenant_rows, two_tenants):
    (row_a, _), (ctx_a, _) = tenant_rows, two_tenants
    user = await make_user(conn, ctx_a)

    with pytest.raises(AuthError):
        await service.login(conn, row_a["slug"], "user@example.com", "wrong password entirely")
    await service.login(conn, row_a["slug"], "user@example.com", PW)

    audit = AuditRepository(conn, ctx_a)
    logins = await audit.list_for_entity("user", str(user["id"]))
    failed = await audit.list_for_entity("user", "user@example.com")
    assert [e["action"] for e in logins] == ["auth.login"]
    assert [e["action"] for e in failed] == ["auth.login_failed"]


# ---------- refresh rotation ----------

async def _login(conn, tenant_rows, two_tenants):
    (row_a, _), (ctx_a, _) = tenant_rows, two_tenants
    user = await make_user(conn, ctx_a)
    pair = await service.login(conn, row_a["slug"], "user@example.com", PW)
    return ctx_a, user, pair


async def test_refresh_rotates_the_token(conn, tenant_rows, two_tenants):
    _, user, first = await _login(conn, tenant_rows, two_tenants)

    second = await service.refresh(conn, first.refresh_token, first.fingerprint)

    assert second.refresh_token != first.refresh_token
    assert second.fingerprint != first.fingerprint
    claims = decode_access_token(second.access_token, second.fingerprint)
    assert claims.user_id == user["id"]

    old = await token_row(conn, first.refresh_token)
    new = await token_row(conn, second.refresh_token)
    assert old["used_at"] is not None
    assert old["replaced_by"] == new["id"]
    assert new["family_id"] == old["family_id"]


async def test_reusing_a_rotated_token_revokes_the_whole_family(conn, tenant_rows, two_tenants):
    ctx_a, user, first = await _login(conn, tenant_rows, two_tenants)
    second = await service.refresh(conn, first.refresh_token, first.fingerprint)

    # The attacker (or a buggy client) presents the OLD token again.
    with pytest.raises(ReuseDetected):
        await service.refresh(conn, first.refresh_token, first.fingerprint)

    # The newest token is dead too: the real user must log in again.
    with pytest.raises(AuthError):
        await service.refresh(conn, second.refresh_token, second.fingerprint)
    row = await token_row(conn, second.refresh_token)
    assert row["revoked_reason"] == "reuse_detected"

    events = await AuditRepository(conn, ctx_a).list_for_entity("user", str(user["id"]))
    assert "auth.refresh_reuse_detected" in [e["action"] for e in events]


async def test_wrong_fingerprint_is_rejected_and_revokes_the_family(conn, tenant_rows, two_tenants):
    _, _, first = await _login(conn, tenant_rows, two_tenants)

    with pytest.raises(AuthError):
        await service.refresh(conn, first.refresh_token, "a-stolen-token-without-the-cookie")

    row = await token_row(conn, first.refresh_token)
    assert row["revoked_reason"] == "fingerprint_mismatch"
    with pytest.raises(AuthError):
        await service.refresh(conn, first.refresh_token, first.fingerprint)


async def test_expired_refresh_token_is_rejected(conn, tenant_rows, two_tenants):
    ctx_a, user, _ = await _login(conn, tenant_rows, two_tenants)
    tokens = RefreshTokenRepository(conn, ctx_a)
    raw, fp = "expired-raw-token-value", "expired-fingerprint-value"
    await tokens.create(
        user_id=user["id"], family_id=uuid4(),
        token_hash=hash_token(raw), fingerprint_hash=hash_token(fp),
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    with pytest.raises(AuthError):
        await service.refresh(conn, raw, fp)


async def test_unknown_refresh_token_is_rejected(conn):
    with pytest.raises(AuthError):
        await service.refresh(conn, "never-issued", "whatever")


async def test_disabled_user_cannot_refresh(conn, tenant_rows, two_tenants):
    _, user, first = await _login(conn, tenant_rows, two_tenants)
    await conn.execute(
        text("update users set is_active = false where id = :id"), {"id": user["id"]}
    )

    with pytest.raises(AuthError):
        await service.refresh(conn, first.refresh_token, first.fingerprint)
    assert (await token_row(conn, first.refresh_token))["revoked_reason"] == "user_disabled"


# ---------- logout ----------

async def test_logout_revokes_the_family(conn, tenant_rows, two_tenants):
    _, _, first = await _login(conn, tenant_rows, two_tenants)
    second = await service.refresh(conn, first.refresh_token, first.fingerprint)

    await service.logout(conn, second.refresh_token)

    with pytest.raises(AuthError):
        await service.refresh(conn, second.refresh_token, second.fingerprint)
    await service.logout(conn, second.refresh_token)  # twice is fine
    await service.logout(conn, "unknown-token")  # unknown is fine


async def test_logout_all_revokes_every_session(conn, tenant_rows, two_tenants):
    (row_a, _), (ctx_a, _) = tenant_rows, two_tenants
    user = await make_user(conn, ctx_a)
    phone = await service.login(conn, row_a["slug"], "user@example.com", PW)
    laptop = await service.login(conn, row_a["slug"], "user@example.com", PW)

    assert await service.logout_all(conn, ctx_a, user["id"]) == 2

    for pair in (phone, laptop):
        with pytest.raises(AuthError):
            await service.refresh(conn, pair.refresh_token, pair.fingerprint)


# ---------- tenant isolation of tokens ----------

async def test_other_tenant_cannot_revoke_a_family(conn, tenant_rows, two_tenants):
    (_, ctx_b) = two_tenants
    _, _, first = await _login(conn, tenant_rows, two_tenants)
    family_id = (await token_row(conn, first.refresh_token))["family_id"]

    revoked = await RefreshTokenRepository(conn, ctx_b).revoke_family(family_id, "attack")

    assert revoked == 0
    assert (await token_row(conn, first.refresh_token))["revoked_at"] is None
    await service.refresh(conn, first.refresh_token, first.fingerprint)  # still works
