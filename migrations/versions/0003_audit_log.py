"""audit_log: append-only system of record for who did what

Revision ID: 0003
Revises: 0002
"""

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create table audit_log (
        id            bigint generated always as identity primary key,
        occurred_at   timestamptz not null default now(),
        tenant_id     uuid not null references tenants (id),
        actor_type    text not null check (actor_type in ('user', 'system', 'agent')),
        actor_user_id uuid,
        action        text not null,
        entity_type   text not null,
        entity_id     text not null,
        request_id    text,
        trace_id      text,
        ip            inet,
        before        jsonb,
        after         jsonb,
        metadata      jsonb not null default '{}'::jsonb,
        foreign key (tenant_id, actor_user_id) references users (tenant_id, id)
    )
    """)
    op.execute("create index ix_audit_tenant_time on audit_log (tenant_id, occurred_at desc)")
    op.execute(
        "create index ix_audit_tenant_entity on audit_log (tenant_id, entity_type, entity_id)"
    )

    # Layer 1: permissions. The API role can only INSERT and SELECT.
    op.execute("revoke update, delete, truncate on audit_log from nyaya_app")

    # Layer 2: triggers. Even the table owner cannot change rows by accident.
    op.execute("""
    create function audit_log_block_change() returns trigger
    language plpgsql as $$
    begin
        raise exception 'audit_log is append-only';
    end;
    $$
    """)
    op.execute("""
    create trigger audit_log_no_update_delete
        before update or delete on audit_log
        for each row execute function audit_log_block_change()
    """)
    op.execute("""
    create trigger audit_log_no_truncate
        before truncate on audit_log
        for each statement execute function audit_log_block_change()
    """)


def downgrade() -> None:
    op.execute("drop table audit_log")
    op.execute("drop function audit_log_block_change()")
