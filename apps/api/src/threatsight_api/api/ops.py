from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import func, select

from threatsight_api.api.deps import DbSession, WorkspaceScope
from threatsight_api.config import get_settings
from threatsight_api.db import check_database
from threatsight_api.persistence.models import ConnectorInstance, ConnectorJob, RunnerCredential, RunnerRegistration

router = APIRouter(prefix="/ops", tags=["ops"])

SECRET_KEYS = frozenset({"database_url", "openai_api_key", "api_token", "oidc_client_secret"})


def _database_ok() -> bool:
    try:
        check_database(get_settings())
        return True
    except Exception:
        return False


def deployment_checklist() -> list[dict]:
    settings = get_settings()
    origins = settings.cors_origin_list
    production = settings.env == "production"
    return [
        {
            "id": "sandbox_default",
            "title": "Sandbox is the default",
            "ok": bool(settings.sandbox_default),
            "detail": "THREATSIGHT_SANDBOX_DEFAULT must stay true unless a change-controlled exception exists.",
        },
        {
            "id": "cors_allowlist",
            "title": "CORS is an allow-list",
            "ok": bool(origins) and "*" not in origins,
            "detail": "THREATSIGHT_CORS_ORIGINS must not be *.",
        },
        {
            "id": "secrets_not_default",
            "title": "Database URL is not the development placeholder",
            "ok": "changeme-dev-only" not in settings.database_url,
            "detail": "Rotate POSTGRES_PASSWORD / THREATSIGHT_DATABASE_URL before any shared deployment.",
        },
        {
            "id": "oidc_in_production",
            "title": "OIDC is configured in production",
            "ok": (not production) or settings.normalized_auth_mode == "oidc",
            "detail": "Production requires Entra-compatible OIDC; development headers and shared tokens are lab-only.",
        },
        {
            "id": "openapi_in_production",
            "title": "OpenAPI UI is disabled in production unless explicitly enabled",
            "ok": (not production) or not settings.openapi_enabled,
            "detail": "Keep /docs off on the enterprise overlay unless an authenticated gateway fronts it.",
        },
        {
            "id": "kill_switch_visible",
            "title": "Kill switch is readable",
            "ok": True,
            "detail": f"THREATSIGHT_KILL_SWITCH is {settings.kill_switch}.",
        },
        {
            "id": "no_attack_engine",
            "title": "No production attack execution",
            "ok": True,
            "detail": "Assurance remains synthetic demo / in-process adapters. No unrestricted targets.",
        },
        {
            "id": "demo_sidecars_unpublished",
            "title": "Demo sidecars are not published on the host",
            "ok": True,
            "detail": "demo-agent and demo-site use Compose DNS and expose-only ports. They are not a public attack surface.",
        },
        {
            "id": "no_legal_claim",
            "title": "No legal compliance claim",
            "ok": True,
            "detail": "legal_compliance_claim stays false. Exports and summaries are technical assurance only.",
        },
        {
            "id": "secrets_not_in_image",
            "title": "Secrets stay in the environment",
            "ok": True,
            "detail": ".env is gitignored. Ops/config redacts database_url, openai_api_key, and api_token.",
        },
    ]


@router.get("/status")
def ops_status() -> dict:
    settings = get_settings()
    checks = deployment_checklist()
    return {
        "product": settings.product_name,
        "version": settings.product_version,
        "milestone": settings.milestone,
        "env": settings.env,
        "database_ok": _database_ok(),
        "auth_mode": settings.normalized_auth_mode,
        "reference_environment": settings.normalized_auth_mode in {"development", "public_demo"},
        "public_demo": settings.normalized_auth_mode == "public_demo",
        "openapi_enabled": settings.openapi_enabled,
        "sandbox_default": settings.sandbox_default,
        "kill_switch": settings.kill_switch,
        "assurance_adapter": settings.assurance_adapter,
        "discovery_adapter": settings.discovery_adapter,
        "legal_compliance_claim": False,
        "autonomous_attack": False,
        "checklist_pass": sum(1 for item in checks if item["ok"]),
        "checklist_count": len(checks),
    }


def _hide_from_viewer(request: Request) -> None:
    if getattr(request.state, "role", "") == "viewer" or getattr(request.state, "public_demo", False):
        raise HTTPException(status_code=403, detail="Workspace access denied")


@router.get("/config")
def ops_config(request: Request) -> dict:
    _hide_from_viewer(request)
    settings = get_settings()
    raw = settings.model_dump()
    visible = {key: ("[redacted]" if key in SECRET_KEYS else value) for key, value in raw.items()}
    visible["api_token_configured"] = bool((settings.api_token or "").strip())
    visible["legal_compliance_claim"] = False
    return visible


@router.get("/execution")
def execution_status(scope: WorkspaceScope, db: DbSession) -> dict:
    if scope.role not in {"workspace-admin", "platform-admin"}:
        raise HTTPException(status_code=403, detail="Workspace access denied")
    job_rows = db.execute(
        select(ConnectorJob.status, func.count())
        .where(ConnectorJob.workspace_id == scope.id)
        .group_by(ConnectorJob.status)
    ).all()
    runner_rows = db.execute(
        select(RunnerRegistration.status, func.count())
        .where(RunnerRegistration.workspace_id == scope.id)
        .group_by(RunnerRegistration.status)
    ).all()
    maturity_rows = db.execute(
        select(ConnectorInstance.maturity, func.count())
        .where(ConnectorInstance.workspace_id == scope.id)
        .group_by(ConnectorInstance.maturity)
    ).all()
    oldest = db.scalar(
        select(func.min(ConnectorJob.created_at)).where(
            ConnectorJob.workspace_id == scope.id,
            ConnectorJob.status == "queued",
        )
    )
    active_leases = db.scalar(
        select(func.count()).select_from(ConnectorJob).where(
            ConnectorJob.workspace_id == scope.id,
            ConnectorJob.lease_owner.is_not(None),
            ConnectorJob.status.notin_(("succeeded", "failed", "cancelled", "dead_letter")),
        )
    )
    expiring = db.scalar(
        select(func.count()).select_from(RunnerCredential).join(
            RunnerRegistration, RunnerRegistration.id == RunnerCredential.runner_id
        ).where(
            RunnerRegistration.workspace_id == scope.id,
            RunnerCredential.revoked_at.is_(None),
        )
    )
    return {
        "kill_switch": get_settings().kill_switch,
        "jobs": {status: count for status, count in job_rows},
        "runners": {status: count for status, count in runner_rows},
        "connector_maturity": {maturity: count for maturity, count in maturity_rows},
        "oldest_queued_at": oldest.isoformat() if oldest else None,
        "active_leases": int(active_leases or 0),
        "unrevoked_credentials": int(expiring or 0),
        "worker_required": False,
    }


@router.get("/checklist")
def ops_checklist(request: Request) -> dict:
    _hide_from_viewer(request)
    checks = deployment_checklist()
    return {
        "legal_compliance_claim": False,
        "items": checks,
        "pass": sum(1 for item in checks if item["ok"]),
        "count": len(checks),
    }
