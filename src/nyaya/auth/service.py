"""Login, refresh-token rotation with reuse detection, and logout.

Rotation in one paragraph: every refresh token can be used exactly once. Using it marks it
"used" and issues a new token in the same family. If a token that was already used shows up
again, somebody has a copy (the attacker or the real user), so the whole family is revoked and
both parties must log in again.

IMPORTANT for the API layer (built later): when refresh() raises AuthError, the revocation it
just did must still be COMMITTED. Do not let a generic "roll back on exception" wrapper undo it.
"""

import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncConnection

from nyaya.auth.passwords import (
    MAX_LENGTH,
    burn_time,
    hash_password,
    needs_rehash,
    verify_password,
)
from nyaya.auth.tokens import create_access_token, hash_token, new_opaque_token
from nyaya.config import get_settings
from nyaya.repositories.audit import AuditRepository
from nyaya.repositories.refresh_tokens import RefreshTokenRepository, find_refresh_token
from nyaya.repositories.tenants import TenantAdminRepository
from nyaya.repositories.users import UserRepository, normalize_email
from nyaya.tenancy import TenantContext

INVALID_CREDENTIALS = "invalid credentials"
INVALID_REFRESH = "invalid refresh token"


class AuthError(Exception):
    """Authentication failed. Messages are generic on purpose."""


class ReuseDetected(AuthError):
    """A used refresh token was presented again; its family has been revoked."""


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    fingerprint: str  # goes into an HttpOnly cookie
    csrf_token: str  # goes into a readable cookie, echoed in a header
    user_id: UUID
    tenant_id: UUID
    refresh_expires_at: datetime


async def _issue(
    conn: AsyncConnection,
    ctx: TenantContext,
    user_id: UUID,
    family_id: UUID,
    token_id: UUID | None = None,
) -> TokenPair:
    settings = get_settings()
    roles = await UserRepository(conn, ctx).list_roles(user_id)

    fingerprint = new_opaque_token()
    refresh_token = new_opaque_token()
    expires_at = datetime.now(UTC) + timedelta(days=settings.refresh_token_ttl_days)

    await RefreshTokenRepository(conn, ctx).create(
        user_id=user_id,
        family_id=family_id,
        token_hash=hash_token(refresh_token),
        fingerprint_hash=hash_token(fingerprint),
        expires_at=expires_at,
        token_id=token_id,
    )
    return TokenPair(
        access_token=create_access_token(user_id, ctx.tenant_id, roles, fingerprint),
        refresh_token=refresh_token,
        fingerprint=fingerprint,
        csrf_token=new_opaque_token(),
        user_id=user_id,
        tenant_id=ctx.tenant_id,
        refresh_expires_at=expires_at,
    )


async def login(
    conn: AsyncConnection,
    tenant_slug: str,
    email: str,
    password: str,
    request_id: str | None = None,
) -> TokenPair:
    if len(password) > MAX_LENGTH:
        raise AuthError(INVALID_CREDENTIALS)

    tenant = await TenantAdminRepository(conn).get_by_slug(tenant_slug)
    if tenant is None or tenant["status"] != "active":
        burn_time(password)
        raise AuthError(INVALID_CREDENTIALS)

    ctx = TenantContext(tenant["id"])
    users = UserRepository(conn, ctx)
    audit = AuditRepository(conn, ctx)

    creds = await users.get_credentials_by_email(email)
    stored_hash = creds["password_hash"] if creds else None
    if stored_hash is None:
        burn_time(password)  # same CPU cost whether or not the account exists
        valid = False
    else:
        valid = verify_password(stored_hash, password)

    if not (valid and creds is not None and stored_hash is not None and creds["is_active"]):
        await audit.record(
            actor_type="system",
            action="auth.login_failed",
            entity_type="user",
            entity_id=normalize_email(email),
            request_id=request_id,
        )
        raise AuthError(INVALID_CREDENTIALS)

    user_id = creds["id"]
    if needs_rehash(stored_hash):
        await users.set_password_hash(user_id, hash_password(password))
    await users.touch_last_login(user_id)

    pair = await _issue(conn, ctx, user_id, family_id=uuid4())
    await audit.record(
        actor_type="user",
        actor_user_id=user_id,
        action="auth.login",
        entity_type="user",
        entity_id=str(user_id),
        request_id=request_id,
    )
    return pair


async def refresh(
    conn: AsyncConnection,
    refresh_token: str,
    fingerprint: str,
    request_id: str | None = None,
) -> TokenPair:
    row = await find_refresh_token(conn, hash_token(refresh_token))
    if row is None:
        raise AuthError(INVALID_REFRESH)

    # From here on, everything is tenant-scoped using the tenant stored on the token row.
    ctx = TenantContext(row["tenant_id"])
    tokens = RefreshTokenRepository(conn, ctx)
    audit = AuditRepository(conn, ctx)

    async def revoke(reason: str, action: str) -> None:
        await tokens.revoke_family(row["family_id"], reason)
        await audit.record(
            actor_type="system",
            action=action,
            entity_type="user",
            entity_id=str(row["user_id"]),
            request_id=request_id,
        )

    if row["revoked_at"] is not None:
        raise AuthError(INVALID_REFRESH)

    if row["used_at"] is not None:
        await revoke("reuse_detected", "auth.refresh_reuse_detected")
        raise ReuseDetected(INVALID_REFRESH)

    if not hmac.compare_digest(hash_token(fingerprint), bytes(row["fingerprint_hash"])):
        await revoke("fingerprint_mismatch", "auth.refresh_fingerprint_mismatch")
        raise AuthError(INVALID_REFRESH)

    if row["expires_at"] <= datetime.now(UTC):
        raise AuthError(INVALID_REFRESH)

    user = await UserRepository(conn, ctx).get_by_id(row["user_id"])
    if user is None or not user["is_active"]:
        await revoke("user_disabled", "auth.refresh_user_disabled")
        raise AuthError(INVALID_REFRESH)

    new_token_id = uuid4()
    if not await tokens.mark_used(row["id"], new_token_id):
        # Lost a race: another request used this token first. Treat it as reuse.
        await revoke("reuse_detected", "auth.refresh_reuse_detected")
        raise ReuseDetected(INVALID_REFRESH)

    return await _issue(conn, ctx, row["user_id"], row["family_id"], token_id=new_token_id)


async def logout(conn: AsyncConnection, refresh_token: str, request_id: str | None = None) -> None:
    """Revoke the whole login chain. Safe to call twice or with an unknown token."""
    row = await find_refresh_token(conn, hash_token(refresh_token))
    if row is None:
        return
    ctx = TenantContext(row["tenant_id"])
    await RefreshTokenRepository(conn, ctx).revoke_family(row["family_id"], "logout")
    await AuditRepository(conn, ctx).record(
        actor_type="user",
        actor_user_id=row["user_id"],
        action="auth.logout",
        entity_type="user",
        entity_id=str(row["user_id"]),
        request_id=request_id,
    )


async def logout_all(conn: AsyncConnection, ctx: TenantContext, user_id: UUID) -> int:
    """Revoke every session of one user (for example after a password change)."""
    count = await RefreshTokenRepository(conn, ctx).revoke_all_for_user(user_id, "logout_all")
    await AuditRepository(conn, ctx).record(
        actor_type="user",
        actor_user_id=user_id,
        action="auth.logout_all",
        entity_type="user",
        entity_id=str(user_id),
    )
    return count
