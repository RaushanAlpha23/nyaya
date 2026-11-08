"""Tenant-scoped audit log access. Insert and read only; there is no update or delete."""

from typing import Any
from uuid import UUID

from nyaya.repositories.base import TenantRepository

_COLUMNS = (
    "id, occurred_at, tenant_id, actor_type, actor_user_id, action, "
    "entity_type, entity_id, request_id, trace_id"
)


class AuditRepository(TenantRepository):
    async def record(
        self,
        *,
        actor_type: str,
        action: str,
        entity_type: str,
        entity_id: str,
        actor_user_id: UUID | None = None,
        request_id: str | None = None,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        row = await self.fetch_one(
            f"""
            insert into audit_log
                (tenant_id, actor_type, actor_user_id, action, entity_type, entity_id,
                 request_id, trace_id)
            values
                (:tenant_id, :actor_type, :actor_user_id, :action, :entity_type, :entity_id,
                 :request_id, :trace_id)
            returning {_COLUMNS}
            """,
            actor_type=actor_type,
            actor_user_id=actor_user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            request_id=request_id,
            trace_id=trace_id,
        )
        assert row is not None
        return row

    async def list_for_entity(self, entity_type: str, entity_id: str) -> list[dict[str, Any]]:
        return await self.fetch_all(
            f"""
            select {_COLUMNS} from audit_log
            where tenant_id = :tenant_id and entity_type = :entity_type and entity_id = :entity_id
            order by id
            """,
            entity_type=entity_type,
            entity_id=entity_id,
        )
