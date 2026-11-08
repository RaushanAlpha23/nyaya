"""Token primitives: access JWT, fingerprint, opaque refresh token, CSRF token.

How the pieces fit together:
- Access token: short-lived signed JWT carrying user, tenant, roles and the SHA-256 of a
  random "fingerprint". The raw fingerprint travels only in an HttpOnly cookie, so a stolen
  JWT alone is useless (the attacker lacks the cookie).
- Refresh token: long random opaque string. Only its SHA-256 is stored (refresh_tokens table).
- CSRF token: random value compared between a cookie and a request header (double submit).
"""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt

from nyaya.config import get_settings

ACCESS_TYPE = "access"


class TokenError(Exception):
    """Raised for any invalid token. The message is deliberately vague."""


@dataclass(frozen=True)
class AccessClaims:
    user_id: UUID
    tenant_id: UUID
    roles: tuple[str, ...]
    jti: str
    expires_at: datetime


def new_opaque_token() -> str:
    """256 bits of randomness, URL-safe. Used for refresh tokens, fingerprints, CSRF."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> bytes:
    """SHA-256 digest. Fine for long random tokens (not for passwords)."""
    return hashlib.sha256(token.encode("utf-8")).digest()


def create_access_token(
    user_id: UUID,
    tenant_id: UUID,
    roles: list[str],
    fingerprint: str,
    now: datetime | None = None,
) -> str:
    settings = get_settings()
    issued = now or datetime.now(UTC)
    payload = {
        "typ": ACCESS_TYPE,
        "sub": str(user_id),
        "tid": str(tenant_id),
        "roles": sorted(roles),
        "jti": uuid4().hex,
        "fgp": hash_token(fingerprint).hex(),
        "iat": int(issued.timestamp()),
        "exp": int((issued + timedelta(minutes=settings.access_token_ttl_minutes)).timestamp()),
    }
    return jwt.encode(
        payload, settings.jwt_secret.get_secret_value(), algorithm=settings.jwt_algorithm
    )


def decode_access_token(token: str, fingerprint: str) -> AccessClaims:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=[settings.jwt_algorithm],  # fixed list: blocks the 'alg: none' trick
            options={"require": ["exp", "iat", "sub", "tid", "fgp", "jti"]},
        )
        if payload.get("typ") != ACCESS_TYPE:
            raise TokenError("invalid token")
        expected = hash_token(fingerprint).hex()
        if not hmac.compare_digest(str(payload["fgp"]), expected):
            raise TokenError("invalid token")
        return AccessClaims(
            user_id=UUID(payload["sub"]),
            tenant_id=UUID(payload["tid"]),
            roles=tuple(payload.get("roles", [])),
            jti=payload["jti"],
            expires_at=datetime.fromtimestamp(payload["exp"], UTC),
        )
    except TokenError:
        raise
    except (jwt.InvalidTokenError, ValueError, KeyError, TypeError) as e:
        raise TokenError("invalid token") from e


def csrf_matches(cookie_value: str | None, header_value: str | None) -> bool:
    if not cookie_value or not header_value:
        return False
    return hmac.compare_digest(cookie_value, header_value)
