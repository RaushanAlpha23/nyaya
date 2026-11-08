"""Shared fixtures.

Every test runs inside ONE transaction that is rolled back at the end, connected as nyaya_app
(the same role the API uses). Nothing is left in Supabase, including audit_log rows that
nyaya_app could not delete anyway.
"""

import uuid

import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from nyaya.db import async_url
from nyaya.repositories.tenants import TenantAdminRepository
from nyaya.tenancy import TenantContext


@pytest_asyncio.fixture
async def conn():
    engine = create_async_engine(async_url(), poolclass=NullPool)
    try:
        async with engine.connect() as connection:
            trans = await connection.begin()
            try:
                yield connection
            finally:
                await trans.rollback()
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def two_tenants(conn):
    admin = TenantAdminRepository(conn)
    a = await admin.create(f"a-{uuid.uuid4().hex[:8]}", "Tenant A")
    b = await admin.create(f"b-{uuid.uuid4().hex[:8]}", "Tenant B")
    return TenantContext(a["id"]), TenantContext(b["id"])
