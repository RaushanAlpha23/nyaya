"""Platform-level access to the tenants table.

This is the ONE repository that is not tenant-scoped, because tenants are the scope itself.
Only admin or onboarding code may use it; request handlers must not.
"""

from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection


class TenantAdminRepository:
    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

    async def create(self, slug: str, name: str) -> dict[str, Any]:
        result = await self._conn.execute(
            text(
                "insert into tenants (slug, name) values (:slug, :name) "
                "returning id, slug, name, status, created_at"
            ),
            {"slug": slug.strip().lower(), "name": name},
        )
        return dict(result.mappings().one())

    async def get_by_slug(self, slug: str) -> dict[str, Any] | None:
        result = await self._conn.execute(
            text("select id, slug, name, status from tenants where slug = :slug"),
            {"slug": slug.strip().lower()},
        )
        row = result.mappings().first()
        return dict(row) if row else None
