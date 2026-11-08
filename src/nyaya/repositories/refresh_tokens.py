"""Refresh token storage.

Two parts:
- find_refresh_token(): platform-level lookup by token hash. This is the ONE place where a
  query is not tenant-scoped, because the client only sends the token and the row itself says
  which tenant it belongs to. The hash is 256 bits of randomness, so it cannot be guessed.
- RefreshTokenRepository: tenant-scoped. Every change after the lookup goes through it, using
  the TenantContext built from the row that was found.
"""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from nyaya.repositories.base import TenantRepository

_COLUMNS = (
    "id, tenant_id, user_id, family_id, token_hash, fingerprint_hash, "
    "issued_at, expires_at, used_at, replaced_by, revoked_at, revoked_reason"
)


async def find_refresh_token(conn: AsyncConnection, token_hash: bytes) -> dict[str, Any] | None:
    result = await conn.execute(
        text(f"select {_COLUMNS} from refresh_tokens where token_hash = :token_hash"),
        {"token_hash": token_hash},
    )
    row = result.mappings().first()
    return dict(row) if row else None


class RefreshTokenRepository(TenantRepository):
    async def create(
        self,
        *,
        user_id: UUID,
        family_id: UUID,
        token_hash: bytes,
        fingerprint_hash: bytes,
        expires_at: datetime,
        token_id: UUID | None = None,
    ) -> dict[str, Any]:
        row = await self.fetch_one(
            f"""
            insert into refresh_tokens
                (id, tenant_id, user_id, family_id, token_hash, fingerprint_hash, expires_at)
            values
                (:token_id, :tenant_id, :user_id, :family_id, :token_hash, :fingerprint_hash,
                 :expires_at)
            returning {_COLUMNS}
            """,
            token_id=token_id or uuid4(),
            user_id=user_id,
            family_id=family_id,
            token_hash=token_hash,
            fingerprint_hash=fingerprint_hash,
            expires_at=expires_at,
        )
        assert row is not None
        return row

    async def mark_used(self, token_id: UUID, replaced_by: UUID) -> bool:
        """Atomically claim a token for rotation.

        Returns False if it was already used or revoked. Two simultaneous refreshes with the
        same token cannot both succeed, because only one UPDATE matches the WHERE clause.
        """
        row = await self.fetch_one(
            """
            update refresh_tokens set used_at = now(), replaced_by = :replaced_by
            where tenant_id = :tenant_id and id = :token_id
              and used_at is null and revoked_at is null
            returning id
            """,
            token_id=token_id,
            replaced_by=replaced_by,
        )
        return row is not None

    async def revoke_family(self, family_id: UUID, reason: str) -> int:
        rows = await self.fetch_all(
            """
            update refresh_tokens set revoked_at = now(), revoked_reason = :reason
            where tenant_id = :tenant_id and family_id = :family_id and revoked_at is null
            returning id
            """,
            family_id=family_id,
            reason=reason,
        )
        return len(rows)

    async def revoke_all_for_user(self, user_id: UUID, reason: str) -> int:
        rows = await self.fetch_all(
            """
            update refresh_tokens set revoked_at = now(), revoked_reason = :reason
            where tenant_id = :tenant_id and user_id = :user_id and revoked_at is null
            returning id
            """,
            user_id=user_id,
            reason=reason,
        )
        return len(rows)
