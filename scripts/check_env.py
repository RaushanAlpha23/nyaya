"""Checks that the credentials in .env actually work. Prints OK/FAIL per store, never secrets.

Run from the repo root:
    pip install pydantic-settings "psycopg[binary]" pymongo qdrant-client redis
    $env:PYTHONPATH="src"          # PowerShell, if nyaya is not installed with pip install -e .
    python scripts/check_env.py
"""

import sys

from nyaya.config import get_settings


def short(err: Exception) -> str:
    # First line only, so long tracebacks and URLs with passwords do not flood the screen.
    return (str(err).splitlines() or [type(err).__name__])[0][:160]


def check_placeholders(settings) -> bool:
    ok = True
    for name, value in settings.model_dump().items():
        raw = value.get_secret_value() if hasattr(value, "get_secret_value") else value
        if isinstance(raw, str) and "PASTE_" in raw:
            print(f"FAIL  {name}: still contains a PASTE_ placeholder")
            ok = False
    return ok


def check_postgres(settings) -> bool:
    import psycopg

    # SQLAlchemy-style prefixes are not understood by psycopg directly.
    dsn = settings.postgres_dsn.get_secret_value()
    dsn = dsn.replace("+asyncpg", "").replace("+psycopg", "")
    try:
        with psycopg.connect(dsn, connect_timeout=10) as conn:
            conn.execute("SELECT 1")
        print("OK    Postgres (Supabase)")
        return True
    except Exception as e:
        print(f"FAIL  Postgres: {short(e)}")
        return False


def check_mongo(settings) -> bool:
    from pymongo import MongoClient

    try:
        client = MongoClient(settings.mongo_uri.get_secret_value(), serverSelectionTimeoutMS=8000)
        client.admin.command("ping")
        print("OK    MongoDB")
        return True
    except Exception as e:
        print(f"FAIL  MongoDB: {short(e)}  (check Atlas Network Access allows your IP)")
        return False


def check_qdrant(settings) -> bool:
    from qdrant_client import QdrantClient

    key = settings.qdrant_api_key.get_secret_value() if settings.qdrant_api_key else None
    try:
        client = QdrantClient(url=settings.qdrant_url, api_key=key, timeout=10)
        client.get_collections()
        print("OK    Qdrant Cloud")
        return True
    except Exception as e:
        print(f"FAIL  Qdrant: {short(e)}")
        return False


def check_redis(settings) -> bool:
    import redis

    try:
        redis.Redis.from_url(settings.redis_url.get_secret_value(), socket_timeout=5).ping()
        print("OK    Redis (Docker)")
        return True
    except Exception as e:
        print(f"FAIL  Redis: {short(e)}  (is the container running?)")
        return False


def main() -> int:
    settings = get_settings()
    if not check_placeholders(settings):
        return 1
    results = [
        check_postgres(settings),
        check_mongo(settings),
        check_qdrant(settings),
    ]
    if "--skip-redis" in sys.argv:
        print("SKIP  Redis (--skip-redis)")
    else:
        results.append(check_redis(settings))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())