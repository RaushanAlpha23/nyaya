"""Auth endpoints.

Access token: returned in the JSON body, kept in memory by the frontend, sent as a Bearer header.
Refresh token and fingerprint: HttpOnly cookies. Refresh and logout rely on cookies, so they
also require the CSRF header (double-submit check).
"""

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from nyaya.api.cookies import (
    CSRF_COOKIE,
    CSRF_HEADER,
    FINGERPRINT_COOKIE,
    REFRESH_COOKIE,
    clear_auth_cookies,
    set_auth_cookies,
)
from nyaya.api.deps import ClaimsDep, RequestIdDep, SessionDep
from nyaya.auth import service
from nyaya.auth.service import AuthError, TokenPair
from nyaya.auth.tokens import csrf_matches
from nyaya.config import get_settings
from nyaya.ratelimit import RateLimiterUnavailable

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    tenant: str = Field(min_length=1, max_length=64)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=512)


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: UUID
    tenant_id: UUID


class MeResponse(BaseModel):
    user_id: UUID
    tenant_id: UUID
    roles: list[str]


def _auth_response(pair: TokenPair) -> AuthResponse:
    return AuthResponse(
        access_token=pair.access_token,
        expires_in=get_settings().access_token_ttl_minutes * 60,
        user_id=pair.user_id,
        tenant_id=pair.tenant_id,
    )


def _require_csrf(request: Request) -> None:
    if not csrf_matches(request.cookies.get(CSRF_COOKIE), request.headers.get(CSRF_HEADER)):
        raise HTTPException(status_code=403, detail="csrf check failed")


def _client_ip(request: Request) -> str:
    # Behind Nginx later, run uvicorn with --proxy-headers and --forwarded-allow-ips so this is
    # the real client address. Never read X-Forwarded-For here yourself: clients can fake it.
    return request.client.host if request.client else "unknown"


@router.post("/login", response_model=AuthResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    session: SessionDep,
    request_id: RequestIdDep,
) -> AuthResponse:
    limiter = request.app.state.limiter
    if limiter is not None:
        try:
            decision = await limiter.login_attempt(_client_ip(request), body.tenant, body.email)
        except RateLimiterUnavailable:
            raise HTTPException(status_code=503, detail="service unavailable") from None
        if not decision.allowed:
            raise HTTPException(
                status_code=429,
                detail="too many attempts",
                headers={"Retry-After": str(decision.retry_after)},
            )

    try:
        pair = await service.login(
            session.conn, body.tenant, body.email, body.password, request_id=request_id
        )
    except AuthError:
        await session.commit()  # keep the failed-login audit entry
        raise HTTPException(status_code=401, detail="invalid credentials") from None
    await session.commit()
    if limiter is not None:
        await limiter.login_succeeded(body.tenant, body.email)
    set_auth_cookies(response, pair)
    return _auth_response(pair)


@router.post("/refresh", response_model=AuthResponse)
async def refresh(
    request: Request, response: Response, session: SessionDep, request_id: RequestIdDep
) -> AuthResponse | JSONResponse:
    _require_csrf(request)
    refresh_token = request.cookies.get(REFRESH_COOKIE)
    fingerprint = request.cookies.get(FINGERPRINT_COOKIE)
    if not refresh_token or not fingerprint:
        raise HTTPException(status_code=401, detail="invalid refresh token")

    try:
        pair = await service.refresh(session.conn, refresh_token, fingerprint, request_id)
    except AuthError:
        # Reuse detection already revoked the family. It MUST be committed, or it is lost.
        await session.commit()
        failed = JSONResponse(status_code=401, content={"detail": "invalid refresh token"})
        clear_auth_cookies(failed)
        return failed
    await session.commit()
    set_auth_cookies(response, pair)
    return _auth_response(pair)


@router.post("/logout", status_code=204)
async def logout(
    request: Request, session: SessionDep, request_id: RequestIdDep
) -> Response:
    _require_csrf(request)
    refresh_token = request.cookies.get(REFRESH_COOKIE)
    if refresh_token:
        await service.logout(session.conn, refresh_token, request_id)
        await session.commit()
    out = Response(status_code=204)
    clear_auth_cookies(out)
    return out


@router.get("/me", response_model=MeResponse)
async def me(claims: ClaimsDep) -> MeResponse:
    return MeResponse(user_id=claims.user_id, tenant_id=claims.tenant_id, roles=list(claims.roles))