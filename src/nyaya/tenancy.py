"""Tenant context: who the current request belongs to.

Built once per request from the VERIFIED access token, never from the request body
or query string. Every tenant-scoped repository requires one.
"""

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class TenantContext:
    tenant_id: UUID
