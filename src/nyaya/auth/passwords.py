"""Password hashing with Argon2id.

Parameters come from settings (OWASP minimum or higher). The stored hash is a self-describing
string, so cost can be raised later and old hashes are upgraded at the next successful login
(see needs_rehash).
"""

from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from nyaya.config import get_settings

MIN_LENGTH = 12  # verify against current OWASP / NIST guidance when finalising
MAX_LENGTH = 128  # stops absurdly long inputs from being used to burn CPU


@lru_cache
def _hasher() -> PasswordHasher:
    s = get_settings()
    return PasswordHasher(
        time_cost=s.argon2_time_cost,
        memory_cost=s.argon2_memory_kib,
        parallelism=s.argon2_parallelism,
    )


def validate_password(password: str) -> None:
    if not (MIN_LENGTH <= len(password) <= MAX_LENGTH):
        raise ValueError(f"Password must be {MIN_LENGTH} to {MAX_LENGTH} characters long")


def hash_password(password: str) -> str:
    validate_password(password)
    return _hasher().hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    """True only if the password matches. Never raises on bad input."""
    if not stored_hash:
        return False
    try:
        return _hasher().verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _hasher().check_needs_rehash(stored_hash)


@lru_cache
def _dummy_hash() -> str:
    return _hasher().hash("dummy-password-for-timing-only")


def burn_time(password: str) -> None:
    """Do the same hashing work when the user does not exist.

    Without this, 'unknown email' returns faster than 'wrong password', which lets an
    attacker discover which emails have accounts.
    """
    verify_password(_dummy_hash(), password)
