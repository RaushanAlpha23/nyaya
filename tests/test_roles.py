"""require_role: 401 without a valid token, 403 without the right role. No database needed."""

from typing import Annotated
from uuid import uuid4

import httpx
import pytest
from fastapi import Depends

from nyaya.api.cookies import FINGERPRINT_COOKIE
from nyaya.api.deps import require_role
from nyaya.auth.tokens import AccessClaims, create_access_token
from nyaya.main import create_app

FP = "test-fingerprint-value"


async def admin_only(claims: Annotated[AccessClaims, Depends(require_role("admin"))]) -> dict:
    return {"user_id": str(claims.user_id)}


async def approver_or_admin(
    claims: Annotated[AccessClaims, Depends(require_role("approver", "admin"))],
) -> dict:
    return {"roles": list(claims.roles)}


@pytest.fixture
def client():
    app = create_app(readiness_checks={})
    app.add_api_route("/t/admin", admin_only)
    app.add_api_route("/t/approve", approver_or_admin)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def headers(roles: list[str], fingerprint: str = FP) -> dict[str, str]:
    token = create_access_token(uuid4(), uuid4(), roles, FP)
    return {"Authorization": f"Bearer {token}", "Cookie": f"{FINGERPRINT_COOKIE}={fingerprint}"}


async def test_user_with_the_role_is_allowed(client):
    assert (await client.get("/t/admin", headers=headers(["admin"]))).status_code == 200


async def test_user_without_the_role_gets_403(client):
    resp = await client.get("/t/admin", headers=headers(["viewer", "adjudicator"]))
    assert resp.status_code == 403


async def test_user_with_no_roles_gets_403(client):
    assert (await client.get("/t/admin", headers=headers([]))).status_code == 403


async def test_any_one_of_several_roles_is_enough(client):
    assert (await client.get("/t/approve", headers=headers(["approver"]))).status_code == 200
    assert (await client.get("/t/approve", headers=headers(["admin"]))).status_code == 200
    assert (await client.get("/t/approve", headers=headers(["viewer"]))).status_code == 403


async def test_no_token_is_401_not_403(client):
    assert (await client.get("/t/admin")).status_code == 401


async def test_right_role_but_wrong_fingerprint_is_401(client):
    resp = await client.get("/t/admin", headers=headers(["admin"], fingerprint="someone-elses"))
    assert resp.status_code == 401
