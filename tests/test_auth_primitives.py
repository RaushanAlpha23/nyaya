"""Pure unit tests: no database needed."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from argon2 import PasswordHasher

from nyaya.auth.passwords import (
    burn_time,
    hash_password,
    needs_rehash,
    validate_password,
    verify_password,
)
from nyaya.auth.tokens import (
    TokenError,
    create_access_token,
    csrf_matches,
    decode_access_token,
    hash_token,
    new_opaque_token,
)
from nyaya.config import get_settings

GOOD_PASSWORD = "correct horse battery staple"


# ---------- passwords ----------

def test_hash_is_argon2id_and_verifies():
    stored = hash_password(GOOD_PASSWORD)
    assert stored.startswith("$argon2id$")
    assert verify_password(stored, GOOD_PASSWORD) is True
    assert verify_password(stored, "wrong password here") is False


def test_same_password_gives_different_hashes():
    assert hash_password(GOOD_PASSWORD) != hash_password(GOOD_PASSWORD)


def test_verify_handles_missing_or_garbage_hash():
    assert verify_password(None, GOOD_PASSWORD) is False
    assert verify_password("", GOOD_PASSWORD) is False
    assert verify_password("not-a-real-hash", GOOD_PASSWORD) is False


def test_password_length_limits():
    with pytest.raises(ValueError):
        validate_password("short")
    with pytest.raises(ValueError):
        validate_password("x" * 200)
    validate_password(GOOD_PASSWORD)


def test_needs_rehash_detects_weaker_parameters():
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(GOOD_PASSWORD)
    assert needs_rehash(weak) is True
    assert needs_rehash(hash_password(GOOD_PASSWORD)) is False


def test_burn_time_never_raises():
    burn_time("anything at all")


# ---------- access tokens ----------

def _token(fingerprint="fp-1", now=None):
    uid, tid = uuid4(), uuid4()
    return uid, tid, create_access_token(uid, tid, ["viewer", "approver"], fingerprint, now=now)


def test_access_token_round_trip():
    uid, tid, token = _token()
    claims = decode_access_token(token, "fp-1")
    assert claims.user_id == uid
    assert claims.tenant_id == tid
    assert claims.roles == ("approver", "viewer")


def test_wrong_fingerprint_is_rejected():
    _, _, token = _token("fp-1")
    with pytest.raises(TokenError):
        decode_access_token(token, "someone-elses-cookie")


def test_expired_token_is_rejected():
    long_ago = datetime.now(UTC) - timedelta(hours=2)
    _, _, token = _token(now=long_ago)
    with pytest.raises(TokenError):
        decode_access_token(token, "fp-1")


def test_token_signed_with_other_key_is_rejected():
    payload = {
        "typ": "access", "sub": str(uuid4()), "tid": str(uuid4()), "roles": [],
        "jti": "x", "fgp": hash_token("fp-1").hex(),
        "iat": int(datetime.now(UTC).timestamp()),
        "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
    }
    forged = jwt.encode(payload, "a-completely-different-secret-key-123456", algorithm="HS256")
    with pytest.raises(TokenError):
        decode_access_token(forged, "fp-1")


def test_alg_none_token_is_rejected():
    payload = {
        "typ": "access", "sub": str(uuid4()), "tid": str(uuid4()), "roles": [],
        "jti": "x", "fgp": hash_token("fp-1").hex(),
        "iat": int(datetime.now(UTC).timestamp()),
        "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
    }
    unsigned = jwt.encode(payload, None, algorithm="none")
    with pytest.raises(TokenError):
        decode_access_token(unsigned, "fp-1")


def test_garbage_token_is_rejected():
    with pytest.raises(TokenError):
        decode_access_token("not.a.jwt", "fp-1")


def test_token_without_required_claims_is_rejected():
    secret = get_settings().jwt_secret.get_secret_value()
    bare = jwt.encode({"sub": str(uuid4())}, secret, algorithm="HS256")
    with pytest.raises(TokenError):
        decode_access_token(bare, "fp-1")


# ---------- opaque tokens and CSRF ----------

def test_opaque_tokens_are_unique_and_hash_is_stable():
    a, b = new_opaque_token(), new_opaque_token()
    assert a != b and len(a) >= 40
    assert hash_token(a) == hash_token(a)
    assert hash_token(a) != hash_token(b)
    assert len(hash_token(a)) == 32


def test_csrf_double_submit():
    token = new_opaque_token()
    assert csrf_matches(token, token) is True
    assert csrf_matches(token, new_opaque_token()) is False
    assert csrf_matches(None, token) is False
    assert csrf_matches(token, None) is False
