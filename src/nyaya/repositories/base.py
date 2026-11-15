"""Base class for every tenant-scoped repository.

Two rules are enforced here, in one place, so there is one thing to audit:
1. A repository cannot be built without a TenantContext.
2. Every query must mention :tenant_id, and the value always comes from the context,
   so a caller cannot pass a different tenant by accident.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from nyaya.tenancy import TenantContext


class TenantRepository:
    def __init__(self, conn: AsyncConnection, ctx: TenantContext) -> None:
        if not isinstance(ctx, TenantContext):
            raise TypeError("A TenantContext is required to build a repository")
        self._conn = conn
        self._ctx = ctx

    @property
    def tenant_id(self) -> UUID:
        return self._ctx.tenant_id

    def _prepare(self, sql: str, params: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
        if ":tenant_id" not in sql:
            raise ValueError("Query must filter or write on :tenant_id")
        # The context value is applied last, so it wins over anything the caller passed.
        return text(sql), {**params, "tenant_id": self._ctx.tenant_id}

    async def fetch_one(self, sql: str, **params: Any) -> dict[str, Any] | None:
        stmt, bound = self._prepare(sql, params)
        row = (await self._conn.execute(stmt, bound)).mappings().first()
        return dict(row) if row else None

    async def fetch_all(self, sql: str, **params: Any) -> list[dict[str, Any]]:
        stmt, bound = self._prepare(sql, params)
        rows = (await self._conn.execute(stmt, bound)).mappings().all()
        return [dict(r) for r in rows]

    async def execute(self, sql: str, **params: Any) -> None:
        stmt, bound = self._prepare(sql, params)
        await self._conn.execute(stmt, bound)