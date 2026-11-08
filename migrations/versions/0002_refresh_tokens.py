"""refresh_tokens: rotation with reuse detection (family chain)

Revision ID: 0002
Revises: 0001
"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create table refresh_tokens (
        id               uuid primary key default gen_random_uuid(),
        tenant_id        uuid not null,
        user_id          uuid not null,
        family_id        uuid not null,
        token_hash       bytea not null unique,
        fingerprint_hash bytea not null,
        issued_at        timestamptz not null default now(),
        expires_at       timestamptz not null,
        used_at          timestamptz,
        replaced_by      uuid,
        revoked_at       timestamptz,
        revoked_reason   text,
        foreign key (tenant_id, user_id) references users (tenant_id, id)
    )
    """)
    op.execute("create index ix_refresh_tokens_family on refresh_tokens (family_id)")
    op.execute(
        "create index ix_refresh_tokens_active_user on refresh_tokens (user_id) "
        "where revoked_at is null"
    )
    op.execute("create index ix_refresh_tokens_expires on refresh_tokens (expires_at)")


def downgrade() -> None:
    op.execute("drop table refresh_tokens")
