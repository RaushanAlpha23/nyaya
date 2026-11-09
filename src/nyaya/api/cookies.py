"""Cookie names and helpers for the auth endpoints.

- refresh cookie: HttpOnly, only sent to /auth/* (so it is not attached to ordinary API calls).
- fingerprint cookie: HttpOnly, sent everywhere; the access token is only valid together with it.
- csrf cookie: readable by the frontend, which echoes it in the X-CSRF-Token header.
"""

from fastapi import Response

from nyaya.auth.service import TokenPair
from nyaya.config import get_settings

REFRESH_COOKIE = "nyaya_rt"
FINGERPRINT_COOKIE = "nyaya_fp"
CSRF_COOKIE = "nyaya_csrf"
CSRF_HEADER = "x-csrf-token"

_AUTH_PATH = "/auth"


def set_auth_cookies(response: Response, pair: TokenPair) -> None:
    settings = get_settings()
    common = {
        "max_age": settings.refresh_token_ttl_days * 86400,
        "secure": settings.cookie_secure,
        "samesite": "strict",
    }
    response.set_cookie(REFRESH_COOKIE, pair.refresh_token, httponly=True, path=_AUTH_PATH, **common)
    response.set_cookie(FINGERPRINT_COOKIE, pair.fingerprint, httponly=True, path="/", **common)
    response.set_cookie(CSRF_COOKIE, pair.csrf_token, httponly=False, path="/", **common)


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(REFRESH_COOKIE, path=_AUTH_PATH)
    response.delete_cookie(FINGERPRINT_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
