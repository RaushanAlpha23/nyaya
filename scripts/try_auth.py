"""Walk through the whole auth flow against a RUNNING server and print what happens.

    python scripts/try_auth.py acme admin@acme.test "a long dev password"

Needs the server on http://127.0.0.1:8000 (override with NYAYA_URL) and the user from seed_dev.py.
The last steps deliberately replay an old refresh token, so this logs the demo user out.
"""

import os
import sys

import httpx

BASE = os.environ.get("NYAYA_URL", "http://127.0.0.1:8000")
RT, FP, CSRF = "nyaya_rt", "nyaya_fp", "nyaya_csrf"  # cookie names (see api/cookies.py)


def show(step: str, resp: httpx.Response, expect: int) -> None:
    mark = "OK  " if resp.status_code == expect else "FAIL"
    print(f"{mark} {step}: HTTP {resp.status_code} (expected {expect})")


def cookie_header(rt: str, fp: str, csrf: str) -> dict[str, str]:
    # Built by hand so we can replay OLD cookies, which a browser would never do by itself.
    return {"Cookie": f"{RT}={rt}; {FP}={fp}; {CSRF}={csrf}", "X-CSRF-Token": csrf}


def main(tenant: str, email: str, password: str) -> None:
    with httpx.Client(base_url=BASE, timeout=30) as http:
        r = http.post("/auth/login", json={"tenant": tenant, "email": email, "password": password})
        show("login", r, 200)
        if r.status_code != 200:
            sys.exit("Login failed: is the user seeded and the server running?")
        token = r.json()["access_token"]
        old = {k: r.cookies.get(k) for k in (RT, FP, CSRF)}
        auth = {"Authorization": f"Bearer {token}"}

        show("GET /auth/me with token + fingerprint cookie", http.get("/auth/me", headers=auth), 200)
        show(
            "GET /auth/me with token but NO fingerprint cookie",
            httpx.get(f"{BASE}/auth/me", headers=auth),
            401,
        )
        show(
            "POST /auth/refresh without CSRF header",
            httpx.post(f"{BASE}/auth/refresh", headers={"Cookie": f"{RT}={old[RT]}; {FP}={old[FP]}; {CSRF}={old[CSRF]}"}),
            403,
        )

        r2 = httpx.post(f"{BASE}/auth/refresh", headers=cookie_header(old[RT], old[FP], old[CSRF]))
        show("POST /auth/refresh with CSRF header (rotation)", r2, 200)
        new = {k: r2.cookies.get(k) for k in (RT, FP, CSRF)}
        print(f"     refresh token changed: {new[RT] != old[RT]}")

        r3 = httpx.post(f"{BASE}/auth/refresh", headers=cookie_header(old[RT], old[FP], old[CSRF]))
        show("REPLAY the old refresh token (reuse detected)", r3, 401)

        r4 = httpx.post(f"{BASE}/auth/refresh", headers=cookie_header(new[RT], new[FP], new[CSRF]))
        show("then the NEW token is dead too (family revoked)", r4, 401)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
