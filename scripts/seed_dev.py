"""Create a tenant and a user for manual testing (committed to the real database).

    python scripts/seed_dev.py acme "Acme Insurance" admin@acme.test "a long dev password" admin

Safe to rerun: an existing tenant or user is reused, not duplicated.
"""

import asyncio
import sys

from nyaya.auth.passwords import hash_password
from nyaya.db import make_engine
from nyaya.repositories.tenants import TenantAdminRepository
from nyaya.repositories.users import UserRepository
from nyaya.tenancy import TenantContext


async def main(slug: str, name: str, email: str, password: str, role: str) -> None:
    engine = make_engine()
    try:
        async with engine.connect() as conn:
            tenant = await TenantAdminRepository(conn).get_by_slug(slug)
            if tenant is None:
                tenant = await TenantAdminRepository(conn).create(slug, name)
                print(f"created tenant {slug}")
            users = UserRepository(conn, TenantContext(tenant["id"]))
            user = await users.get_by_email(email)
            if user is None:
                user = await users.create(email, password_hash=hash_password(password))
                print(f"created user {email}")
            if role not in await users.list_roles(user["id"]):
                await users.assign_role(user["id"], role)
                print(f"granted role {role}")
            await conn.commit()
    finally:
        await engine.dispose()


if __name__ == "__main__":
    if len(sys.argv) != 6:
        sys.exit(__doc__)
    asyncio.run(main(*sys.argv[1:]))
