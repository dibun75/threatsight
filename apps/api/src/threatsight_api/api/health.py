from fastapi import APIRouter, HTTPException
from sqlalchemy.exc import SQLAlchemyError

from threatsight_api.config import get_settings
from threatsight_api.db import check_database
from threatsight_api.persistence.session import SessionLocal
from threatsight_api.public_demo import demo_boundary_problems

router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    settings = get_settings()
    return {
        "status": "ok",
        "service": "threatsight-api",
        "milestone": settings.milestone,
    }


@router.get("/ready")
def ready() -> dict:
    settings = get_settings()
    try:
        check_database(settings)
        if settings.normalized_auth_mode == "public_demo":
            with SessionLocal() as session:
                problems = demo_boundary_problems(session, settings)
            if problems:
                raise HTTPException(status_code=503, detail={"status": "unavailable", "checks": {"demo": "refused"}})
    except HTTPException:
        raise
    except (SQLAlchemyError, OSError) as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "unavailable",
                "checks": {"database": "error", "detail": type(exc).__name__},
            },
        ) from exc
    return {"status": "ok", "checks": {"database": "ok"}}
