"""Readiness checks. /ready names exactly which store is failing (M0 "done when").

Only the exception TYPE is reported, never its message, because messages can contain
hostnames or credentials.
"""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from nyaya.config import get_settings

Check = Callable[[], Awaitable[None]]
CHECK_TIMEOUT_SECONDS = 8


def default_checks(get_engine: Callable[[], AsyncEngine]) -> dict[str, Check]:
    settings = get_settings()

    async def postgres() -> None:
        async with get_engine().connect() as conn:
            await conn.execute(text("select 1"))

    async def mongo() -> None:
        from pymongo import MongoClient

        def ping() -> None:
            client: MongoClient[Any] = MongoClient(
                settings.mongo_uri.get_secret_value(), serverSelectionTimeoutMS=5000
            )
            try:
                client.admin.command("ping")
            finally:
                client.close()

        await asyncio.to_thread(ping)

    async def qdrant() -> None:
        from qdrant_client import QdrantClient

        def ping() -> None:
            key = settings.qdrant_api_key.get_secret_value() if settings.qdrant_api_key else None
            client = QdrantClient(url=settings.qdrant_url, api_key=key, timeout=5)
            try:
                client.get_collections()
            finally:
                client.close()

        await asyncio.to_thread(ping)

    async def redis() -> None:
        import redis.asyncio as aioredis

        client = aioredis.Redis.from_url(settings.redis_url.get_secret_value(), socket_timeout=5)
        try:
            await client.ping()
        finally:
            await client.aclose()

    return {"postgres": postgres, "mongo": mongo, "qdrant": qdrant, "redis": redis}


async def run_checks(checks: dict[str, Check]) -> dict[str, Any]:
    results: dict[str, str] = {}

    async def one(name: str, check: Check) -> None:
        try:
            await asyncio.wait_for(check(), timeout=CHECK_TIMEOUT_SECONDS)
            results[name] = "ok"
        except Exception as e:  # noqa: BLE001 - any failure means "not ready"
            results[name] = f"fail: {type(e).__name__}"

    await asyncio.gather(*(one(name, check) for name, check in checks.items()))
    return results
