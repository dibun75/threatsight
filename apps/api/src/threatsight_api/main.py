from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from threatsight_api.api.assurance import findings_router, router as assurance_router
from threatsight_api.api.auth import router as auth_router
from threatsight_api.api.connectivity import router as connectivity_router
from threatsight_api.api.connectors import router as connectors_router, runner_router
from threatsight_api.api.dashboard import router as dashboard_router
from threatsight_api.api.discovery import router as discovery_router
from threatsight_api.api.documents import candidates_router, documents_router
from threatsight_api.api.evidence import router as evidence_router
from threatsight_api.api.frameworks import router as framework_catalog_router
from threatsight_api.api.activity import router as activity_router
from threatsight_api.api.analysis import router as analysis_router
from threatsight_api.api.correlation import router as correlation_router
from threatsight_api.api.decisions import router as decisions_router
from threatsight_api.api.graph import router as graph_router
from threatsight_api.api.investigations import router as investigations_router
from threatsight_api.api.telemetry import router as telemetry_router
from threatsight_api.api.greynoise import router as greynoise_router
from threatsight_api.api.threats import router as threats_router
from threatsight_api.api.multisource import router as multisource_router
from threatsight_api.api.governance import (
    audit_router,
    frameworks_router,
    reviews_router,
)
from threatsight_api.api.landscape import router as landscape_router
from threatsight_api.api.local_auth import router as local_auth_router
from threatsight_api.api.radar import router as radar_router
from threatsight_api.api.radar_workflows import router as radar_workflows_router
from threatsight_api.api.readiness import router as readiness_router
from threatsight_api.api.readiness_actions import router as readiness_actions_router
from threatsight_api.api.signing import router as signing_router
from threatsight_api.api.response import router as response_router
from threatsight_api.api.exports import router as exports_router
from threatsight_api.api.integrations import router as integrations_router
from threatsight_api.api.settings import router as settings_router
from threatsight_api.api.health import router as health_router
from threatsight_api.api.intelligence import router as intelligence_router
from threatsight_api.api.ops import router as ops_router
from threatsight_api.api.metrics import router as metrics_router
from threatsight_api.api.meta import router as meta_router
from threatsight_api.api.showcase import router as showcase_router
from threatsight_api.api.requirements import router as requirements_router
from threatsight_api.api.systems import controls_router, systems_router
from threatsight_api.authz import AuthzMiddleware
from threatsight_api.config import get_settings
from threatsight_api.db import run_migrations
from threatsight_api.logging import configure_logging
from threatsight_api.middleware import RequestContextMiddleware
from threatsight_api.persistence.session import SessionLocal, configure_engine
from threatsight_api.public_demo import ensure_demo_viewer


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(json_logs=settings.log_json, level=settings.log_level)
    if settings.run_migrations:
        run_migrations(settings)
    configure_engine()
    if settings.normalized_auth_mode == "public_demo":
        with SessionLocal() as session:
            ensure_demo_viewer(session, settings)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    settings.validate_runtime_security()
    openapi = settings.openapi_enabled
    application = FastAPI(
        title="ThreatSight API",
        version=settings.product_version,
        lifespan=lifespan,
        docs_url="/docs" if openapi else None,
        redoc_url="/redoc" if openapi else None,
        openapi_url="/openapi.json" if openapi else None,
    )
    application.add_middleware(RequestContextMiddleware)
    application.add_middleware(AuthzMiddleware)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "HEAD", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-API-Token",
            "X-Actor",
            "X-Role",
            "X-Request-ID",
            "X-Workspace-Key",
        ],
    )
    application.include_router(health_router)
    application.include_router(auth_router, prefix="/api/v1")
    application.include_router(local_auth_router, prefix="/api/v1")
    application.include_router(meta_router, prefix="/api/v1")
    application.include_router(ops_router, prefix="/api/v1")
    application.include_router(metrics_router, prefix="/api/v1")
    application.include_router(showcase_router, prefix="/api/v1")
    application.include_router(exports_router, prefix="/api/v1")
    application.include_router(integrations_router, prefix="/api/v1")
    application.include_router(settings_router, prefix="/api/v1")
    application.include_router(dashboard_router, prefix="/api/v1")
    application.include_router(systems_router, prefix="/api/v1")
    application.include_router(requirements_router, prefix="/api/v1")
    application.include_router(controls_router, prefix="/api/v1")
    application.include_router(evidence_router, prefix="/api/v1")
    application.include_router(documents_router, prefix="/api/v1")
    application.include_router(candidates_router, prefix="/api/v1")
    application.include_router(assurance_router, prefix="/api/v1")
    application.include_router(findings_router, prefix="/api/v1")
    application.include_router(radar_router, prefix="/api/v1")
    application.include_router(landscape_router, prefix="/api/v1")
    application.include_router(radar_workflows_router, prefix="/api/v1")
    application.include_router(discovery_router, prefix="/api/v1")
    application.include_router(threats_router, prefix="/api/v1")
    application.include_router(multisource_router, prefix="/api/v1")
    application.include_router(intelligence_router, prefix="/api/v1")
    application.include_router(connectivity_router, prefix="/api/v1")
    application.include_router(connectors_router, prefix="/api/v1")
    application.include_router(graph_router, prefix="/api/v1")
    application.include_router(analysis_router, prefix="/api/v1")
    application.include_router(correlation_router, prefix="/api/v1")
    application.include_router(decisions_router, prefix="/api/v1")
    application.include_router(readiness_router, prefix="/api/v1")
    application.include_router(readiness_actions_router, prefix="/api/v1")
    application.include_router(signing_router, prefix="/api/v1")
    application.include_router(response_router, prefix="/api/v1")
    application.include_router(investigations_router, prefix="/api/v1")
    application.include_router(telemetry_router, prefix="/api/v1")
    application.include_router(greynoise_router, prefix="/api/v1")
    application.include_router(activity_router, prefix="/api/v1")
    application.include_router(runner_router, prefix="/api/v1")
    application.include_router(framework_catalog_router, prefix="/api/v1")
    application.include_router(frameworks_router, prefix="/api/v1")
    application.include_router(reviews_router, prefix="/api/v1")
    application.include_router(audit_router, prefix="/api/v1")
    return application


app = create_app()
