"""Liveness and readiness.

/health: the process is up (no dependencies touched).
/ready: every datastore answers; the response names any failing store.
"""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from nyaya.health import run_checks

router = APIRouter(tags=["ops"])


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
async def ready(request: Request) -> JSONResponse:
    results = await run_checks(request.app.state.readiness_checks)
    all_ok = all(value == "ok" for value in results.values())
    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={"status": "ready" if all_ok else "not_ready", "checks": results},
    )
