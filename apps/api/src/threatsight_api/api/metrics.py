"""Safe operational telemetry in OpenMetrics text format.

No secrets, tokens, emails, raw sensitive URLs, or high-cardinality tenant IDs.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError

from threatsight_api.api.deps import DbSession
from threatsight_api.config import get_settings
from threatsight_api.db import check_database
from threatsight_api.persistence.models import EvidenceSigningRequest

router = APIRouter(prefix="/ops", tags=["ops-metrics"])


def _require_ops_role(request: Request) -> None:
    role = getattr(request.state, "role", "") or ""
    if role in {"operator", "workspace-admin", "platform-admin", "auditor", "metrics-scraper"}:
        return
    settings = get_settings()
    if not settings.ops_metrics_public:
        raise HTTPException(status_code=401, detail="Authentication required")


@router.get("/metrics")
def ops_metrics(request: Request, db: DbSession) -> Response:
    _require_ops_role(request)
    settings = get_settings()
    lines: list[str] = [
        "# HELP threatsight_up 1 if process is serving",
        "# TYPE threatsight_up gauge",
        "threatsight_up 1",
        "# HELP threatsight_info Build/profile labels (bounded)",
        "# TYPE threatsight_info gauge",
        (
            f'threatsight_info{{env="{settings.env}",profile="{settings.deployment_profile}",'
            f'version="{settings.product_version}"}} 1'
        ),
    ]
    db_ok = 0
    try:
        check_database(settings)
        db_ok = 1
    except (SQLAlchemyError, OSError, RuntimeError, ValueError):
        db_ok = 0
    lines += [
        "# HELP threatsight_database_up 1 if database ping succeeds",
        "# TYPE threatsight_database_up gauge",
        f"threatsight_database_up {db_ok}",
    ]
    try:
        schema = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
        lines += [
            "# HELP threatsight_schema_info Alembic revision label",
            "# TYPE threatsight_schema_info gauge",
            f'threatsight_schema_info{{revision="{schema}"}} 1',
        ]
    except SQLAlchemyError:
        lines += [
            "# HELP threatsight_schema_info Alembic revision label",
            "# TYPE threatsight_schema_info gauge",
            'threatsight_schema_info{revision="unknown"} 0',
        ]
    try:
        pending = db.scalar(
            select(func.count()).select_from(EvidenceSigningRequest).where(
                EvidenceSigningRequest.state.in_(("pending", "leased"))
            )
        )
        backlog = int(pending or 0)
    except SQLAlchemyError:
        backlog = 0
    lines += [
        "# HELP threatsight_signing_backlog Pending+leased signing requests",
        "# TYPE threatsight_signing_backlog gauge",
        f"threatsight_signing_backlog {backlog}",
    ]
    body = "\n".join(lines) + "\n"
    return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")
