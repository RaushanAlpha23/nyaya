"""identity tables: tenants, users, roles, user_roles

Revision ID: 0001
Revises:
"""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create table tenants (
        id         uuid primary key default gen_random_uuid(),
        slug       text not null unique check (slug = lower(slug)),
        name       text not null,
        status     text not null default 'active' check (status in ('active', 'suspended')),
        created_at timestamptz not null default now()
    )
    """)

    op.execute("""
    create table users (
        id            uuid primary key default gen_random_uuid(),
        tenant_id     uuid not null references tenants (id),
        email         text not null check (email = lower(email)),
        password_hash text,
        display_name  text,
        is_active     boolean not null default true,
        created_at    timestamptz not null default now(),
        last_login_at timestamptz,
        unique (tenant_id, email),
        unique (tenant_id, id)
    )
    """)

    op.execute("""
    create table roles (
        name        text primary key,
        description text
    )
    """)

    op.execute("""
    insert into roles (name, description) values
        ('admin',       'Manage users and tenant settings'),
        ('adjudicator', 'Run and edit claim adjudications'),
        ('approver',    'Approve or reject decisions'),
        ('viewer',      'Read-only access')
    """)

    op.execute("""
    create table user_roles (
        tenant_id  uuid not null,
        user_id    uuid not null,
        role_name  text not null references roles (name),
        granted_at timestamptz not null default now(),
        primary key (user_id, role_name),
        foreign key (tenant_id, user_id) references users (tenant_id, id)
    )
    """)
    op.execute("create index ix_user_roles_tenant_role on user_roles (tenant_id, role_name)")


def downgrade() -> None:
    op.execute("drop table user_roles")
    op.execute("drop table roles")
    op.execute("drop table users")
    op.execute("drop table tenants")
