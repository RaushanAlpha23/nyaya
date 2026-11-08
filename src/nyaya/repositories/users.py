"""Tenant-scoped access to users and their roles."""

from typing import Any
from uuid import UUID

from nyaya.repositories.base import TenantRepository

_USER_COLUMNS = "id, tenant_id, email, display_name, is_active, created_at"


def normalize_email(email: str) -> str:
    return email.strip().lower()


class UserRepository(TenantRepository):
    async def create(
        self,
        email: str,
        password_hash: str | None = None,
        display_name: str | None = None,
    ) -> dict[str, Any]:
        row = await self.fetch_one(
            f"""
            insert into users (tenant_id, email, password_hash, display_name)
            values (:tenant_id, :email, :password_hash, :display_name)
            returning {_USER_COLUMNS}
            """,
            email=normalize_email(email),
            password_hash=password_hash,
            display_name=display_name,
        )
        assert row is not None
        return row

    async def get_by_id(self, user_id: UUID) -> dict[str, Any] | None:
        return await self.fetch_one(
            f"select {_USER_COLUMNS} from users where tenant_id = :tenant_id and id = :user_id",
            user_id=user_id,
        )

    async def get_by_email(self, email: str) -> dict[str, Any] | None:
        return await self.fetch_one(
            f"select {_USER_COLUMNS} from users where tenant_id = :tenant_id and email = :email",
            email=normalize_email(email),
        )

    async def get_credentials_by_email(self, email: str) -> dict[str, Any] | None:
        """For login only. This is the one query that returns password_hash."""
        return await self.fetch_one(
            "select id, email, password_hash, is_active from users "
            "where tenant_id = :tenant_id and email = :email",
            email=normalize_email(email),
        )

    async def set_password_hash(self, user_id: UUID, password_hash: str) -> None:
        await self.execute(
            "update users set password_hash = :password_hash "
            "where tenant_id = :tenant_id and id = :user_id",
            user_id=user_id,
            password_hash=password_hash,
        )

    async def touch_last_login(self, user_id: UUID) -> None:
        await self.execute(
            "update users set last_login_at = now() where tenant_id = :tenant_id and id = :user_id",
            user_id=user_id,
        )

    async def assign_role(self, user_id: UUID, role_name: str) -> None:
        # The composite FK (tenant_id, user_id) makes the database reject a user from another tenant.
        await self.execute(
            """
            insert into user_roles (tenant_id, user_id, role_name)
            values (:tenant_id, :user_id, :role_name)
            """,
            user_id=user_id,
            role_name=role_name,
        )

    async def list_roles(self, user_id: UUID) -> list[str]:
        rows = await self.fetch_all(
            "select role_name from user_roles where tenant_id = :tenant_id and user_id = :user_id "
            "order by role_name",
            user_id=user_id,
        )
        return [r["role_name"] for r in rows]
