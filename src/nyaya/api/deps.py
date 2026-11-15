"""FastAPI dependencies.

Session: one database connection per request. Nothing is committed unless the endpoint calls
session.commit(), and an unfinished connection is rolled back when it closes. Auth endpoints
commit on purpose even when they return 401, so revocations and audit entries are kept.

get_tenant: builds the TenantContext from the VERIFIED access token, never from the body.
"""

from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncConnection

from nyaya.api.cookies import FINGERPRINT_COOKIE
from nyaya.auth.tokens import AccessClaims, TokenError, decode_access_token
from nyaya.tenancy import TenantContext


class Session:
    def __init__(self, conn: AsyncConnection) -> None:
        self.conn = conn

    async def commit(self) -> None:
        await self.conn.commit()


async def get_session(request: Request) -> AsyncIterator[Session]:
    async with request.app.state.engine.connect() as conn:
        yield Session(conn)


def get_request_id(request: Request) -> str:
    return str(request.state.request_id)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=401, detail="not authenticated", headers={"WWW-Authenticate": "Bearer"}
    )


async def get_claims(request: Request) -> AccessClaims:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    fingerprint = request.cookies.get(FINGERPRINT_COOKIE)
    if scheme.lower() != "bearer" or not token or not fingerprint:
        raise _unauthorized()
    try:
        return decode_access_token(token, fingerprint)
    except TokenError:
        raise _unauthorized() from None


async def get_tenant(claims: Annotated[AccessClaims, Depends(get_claims)]) -> TenantContext:
    return TenantContext(claims.tenant_id)


SessionDep = Annotated[Session, Depends(get_session)]
RequestIdDep = Annotated[str, Depends(get_request_id)]
ClaimsDep = Annotated[AccessClaims, Depends(get_claims)]
TenantDep = Annotated[TenantContext, Depends(get_tenant)]


def require_role(*allowed: str) -> Callable[[AccessClaims], Awaitable[AccessClaims]]:
    """Dependency factory: allow the request only if the user holds at least one of the roles.

        @router.post("/approve")
        async def approve(claims: Annotated[AccessClaims, Depends(require_role("approver"))]): ...

    Roles come from the access token, so a role change takes effect when the current access token
    expires (15 minutes by default), not instantly. Side-effect tools re-check approvals in code.
    """
    wanted = frozenset(allowed)

    async def checker(claims: ClaimsDep) -> AccessClaims:
        if wanted.isdisjoint(claims.roles):
            raise HTTPException(status_code=403, detail="forbidden")
        return claims

    return checker