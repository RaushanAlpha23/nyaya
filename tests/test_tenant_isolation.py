"""M1 "done when": proves tenant A cannot read or write tenant B's data."""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from nyaya.repositories.audit import AuditRepository
from nyaya.repositories.users import UserRepository


async def test_same_email_allowed_in_two_tenants(conn, two_tenants):
    ctx_a, ctx_b = two_tenants
    user_a = await UserRepository(conn, ctx_a).create("Shared@Example.com")
    user_b = await UserRepository(conn, ctx_b).create("shared@example.com")
    assert user_a["id"] != user_b["id"]
    assert user_a["email"] == user_b["email"] == "shared@example.com"


async def test_duplicate_email_in_same_tenant_rejected(conn, two_tenants):
    ctx_a, _ = two_tenants
    users_a = UserRepository(conn, ctx_a)
    await users_a.create("dup@example.com")
    with pytest.raises(IntegrityError):
        async with conn.begin_nested():
            await users_a.create("DUP@example.com")


async def test_cross_tenant_read_by_id_returns_nothing(conn, two_tenants):
    ctx_a, ctx_b = two_tenants
    user_b = await UserRepository(conn, ctx_b).create("only-in-b@example.com")
    assert await UserRepository(conn, ctx_a).get_by_id(user_b["id"]) is None
    assert await UserRepository(conn, ctx_b).get_by_id(user_b["id"]) is not None


async def test_cross_tenant_read_by_email_returns_own_user(conn, two_tenants):
    ctx_a, ctx_b = two_tenants
    user_a = await UserRepository(conn, ctx_a).create("same@example.com")
    user_b = await UserRepository(conn, ctx_b).create("same@example.com")
    found_a = await UserRepository(conn, ctx_a).get_by_email("same@example.com")
    found_b = await UserRepository(conn, ctx_b).get_by_email("same@example.com")
    assert found_a["id"] == user_a["id"]
    assert found_b["id"] == user_b["id"]


async def test_caller_cannot_override_tenant(conn, two_tenants):
    ctx_a, ctx_b = two_tenants
    user_b = await UserRepository(conn, ctx_b).create("victim@example.com")
    users_a = UserRepository(conn, ctx_a)
    # Even if the caller passes tenant B's id, the context value wins.
    row = await users_a.fetch_one(
        "select id from users where tenant_id = :tenant_id and id = :user_id",
        tenant_id=ctx_b.tenant_id,
        user_id=user_b["id"],
    )
    assert row is None


async def test_query_without_tenant_filter_is_refused(conn, two_tenants):
    ctx_a, _ = two_tenants
    with pytest.raises(ValueError):
        await UserRepository(conn, ctx_a).fetch_one("select id from users")


async def test_repository_requires_tenant_context(conn):
    with pytest.raises(TypeError):
        UserRepository(conn, None)  # type: ignore[arg-type]


async def test_cannot_assign_role_to_another_tenants_user(conn, two_tenants):
    ctx_a, ctx_b = two_tenants
    user_b = await UserRepository(conn, ctx_b).create("target@example.com")
    with pytest.raises(IntegrityError):
        async with conn.begin_nested():
            await UserRepository(conn, ctx_a).assign_role(user_b["id"], "viewer")


async def test_role_assignment_works_inside_a_tenant(conn, two_tenants):
    ctx_a, _ = two_tenants
    users_a = UserRepository(conn, ctx_a)
    user = await users_a.create("approver@example.com")
    await users_a.assign_role(user["id"], "approver")
    await users_a.assign_role(user["id"], "viewer")
    assert await users_a.list_roles(user["id"]) == ["approver", "viewer"]


async def test_audit_entries_are_tenant_scoped(conn, two_tenants):
    ctx_a, ctx_b = two_tenants
    await AuditRepository(conn, ctx_a).record(
        actor_type="system", action="decision.approved", entity_type="decision", entity_id="d-1"
    )
    assert len(await AuditRepository(conn, ctx_a).list_for_entity("decision", "d-1")) == 1
    assert await AuditRepository(conn, ctx_b).list_for_entity("decision", "d-1") == []


async def test_audit_log_rejects_update_delete_truncate(conn, two_tenants):
    ctx_a, _ = two_tenants
    await AuditRepository(conn, ctx_a).record(
        actor_type="system", action="test", entity_type="x", entity_id="1"
    )
    for statement in (
        "update audit_log set action = 'tampered'",
        "delete from audit_log",
        "truncate audit_log",
    ):
        with pytest.raises(DBAPIError):
            async with conn.begin_nested():
                await conn.execute(text(statement))
