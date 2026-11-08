"""Database engine for the API. Connects as nyaya_app (no DDL, limited audit rights)."""

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from nyaya.config import get_settings


def async_url() -> str:
    dsn = get_settings().postgres_dsn.get_secret_value()
    # Force the asyncpg driver whatever prefix the .env value has.
    return "postgresql+asyncpg://" + dsn.split("://", 1)[1]


def make_engine() -> AsyncEngine:
    settings = get_settings()
    return create_async_engine(async_url(), pool_size=settings.postgres_pool_size)
