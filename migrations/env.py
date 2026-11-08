"""Alembic environment.

Connects as nyaya_migrator (the role that owns the schema), never as nyaya_app.
Migrations are plain SQL, so there is no SQLAlchemy model metadata.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from nyaya.config import get_settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = None


def get_url() -> str:
    dsn = get_settings().postgres_migrator_dsn.get_secret_value()
    # Force the psycopg (v3) driver whatever prefix the .env value has.
    rest = dsn.split("://", 1)[1]
    return "postgresql+psycopg://" + rest


def run_migrations_offline() -> None:
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        version_table_schema="nyaya",
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(
        get_url(),
        poolclass=pool.NullPool,
        connect_args={"options": "-csearch_path=nyaya"},
    )
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table_schema="nyaya",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
