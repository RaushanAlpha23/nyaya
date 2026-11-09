"""FastAPI application.

Run locally (from the repo root, with PYTHONPATH=src or an editable install):
    uvicorn nyaya.main:app --reload
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, Request
from sqlalchemy.ext.asyncio import AsyncEngine

from nyaya.api import routes_auth, routes_health
from nyaya.config import get_settings
from nyaya.db import make_engine
from nyaya.health import Check, default_checks
from nyaya.ratelimit import RateLimiter, make_redis_client


def create_app(
    engine: AsyncEngine | None = None,
    readiness_checks: dict[str, Check] | None = None,
    limiter: RateLimiter | None = None,
) -> FastAPI:
    owns_engine = engine is None
    owns_limiter = limiter is None

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        redis_client = None
        if owns_engine:
            app.state.engine = make_engine()
        if owns_limiter:
            redis_client = make_redis_client(get_settings().redis_url.get_secret_value())
            app.state.limiter = RateLimiter.from_settings(redis_client)
        yield
        if redis_client is not None:
            await redis_client.aclose()
        if owns_engine:
            await app.state.engine.dispose()

    app = FastAPI(title="Nyaya", lifespan=lifespan)
    app.state.limiter = limiter  # None means no rate limiting (tests); lifespan creates one
    if engine is not None:
        app.state.engine = engine
    app.state.readiness_checks = readiness_checks or default_checks(lambda: app.state.engine)

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
        request.state.request_id = request.headers.get("x-request-id") or uuid4().hex
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    app.include_router(routes_health.router)
    app.include_router(routes_auth.router)
    return app


app = create_app()