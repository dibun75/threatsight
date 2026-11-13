from __future__ import annotations

import hmac
import secrets
import time

from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from threatsight_api.config import get_settings
from threatsight_api.integrations import tokens as api_tokens
from threatsight_api.oidc import (
    CANONICAL_ROLES,
    CSRF_COOKIE,
    ROLE_ALIASES,
    browser_cookie_name,
    canonical_role,
    presented_authentication_token,
    resolve_session,
)
from threatsight_api.url_safety import origin_of
from threatsight_api.persistence.session import SessionLocal

ROLES = CANONICAL_ROLES | frozenset(ROLE_ALIASES)
WRITE_ROLES = frozenset({"operator", "workspace-admin", "platform-admin", "reviewer", "admin"})
PUBLIC_PATHS = frozenset({"/health", "/ready"})
PUBLIC_PREFIXES = (
    "/docs", "/redoc", "/openapi.json", "/api/v1/auth/login",
    "/api/v1/auth/callback", "/api/v1/auth/status",
    "/api/v1/auth/local/login", "/api/v1/auth/local/activate", "/api/v1/auth/local/reset",
    "/api/v1/runner/v1/",
)
API_TOKEN_BLOCKED_PREFIXES = ("/api/v1/auth/", "/api/v1/integrations/", "/api/v1/settings")
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_PUBLIC_WINDOW = {"start": 0.0, "count": 0}
_EXPENSIVE_WINDOW = {"start": 0.0, "count": 0}
PUBLIC_DEMO_LIMIT = 600
PUBLIC_DEMO_EXPENSIVE_LIMIT = 60
EXPENSIVE_PREFIXES = ("/api/v1/graph/", "/api/v1/analysis/", "/api/v1/correlation/", "/api/v1/landscape/", "/api/v1/decisions/", "/api/v1/activity/", "/api/v1/investigations/", "/api/v1/telemetry/", "/api/v1/readiness/", "/api/v1/readiness/actions/", "/api/v1/evidence/signing/")


def _take_window(window: dict[str, float], limit: int) -> bool:
    now = time.monotonic()
    if now - window["start"] >= 60:
        window["start"] = now
        window["count"] = 0
    window["count"] += 1
    return window["count"] <= limit


def public_demo_request_allowed(path: str) -> bool:
    """Single-process limits. They are not distributed and they do not use a client IP.

    Graph, analysis, correlation, and landscape reads also use a smaller budget so one visitor
    cannot spend the whole general allowance on those routes.
    """
    if not _take_window(_PUBLIC_WINDOW, PUBLIC_DEMO_LIMIT):
        return False
    if any(path.startswith(prefix) for prefix in EXPENSIVE_PREFIXES):
        return _take_window(_EXPENSIVE_WINDOW, PUBLIC_DEMO_EXPENSIVE_LIMIT)
    return True


def token_matches(provided: str, expected: str) -> bool:
    if not provided or not expected:
        return False
    if len(provided.encode()) != len(expected.encode()):
        secrets.compare_digest(provided.encode(), provided.encode())
        return False
    return hmac.compare_digest(provided.encode(), expected.encode())


def extract_token(request: Request) -> str:
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return (request.headers.get("x-api-token") or "").strip()


def development_request_role(request: Request) -> str:
    role = (request.headers.get("x-role") or "operator").strip().lower()
    if not role:
        role = "operator"
    if role not in ROLES:
        raise HTTPException(status_code=400, detail="Invalid X-Role header")
    return role


def role_may_write(role: str) -> bool:
    return role in WRITE_ROLES or ROLE_ALIASES.get(role) in WRITE_ROLES


def allowed_browser_origins(settings) -> set[str]:
    origins = {origin.rstrip("/") for origin in [*settings.cors_origin_list, *settings.web_origin_list]}
    redirect_origin = origin_of(settings.oidc_redirect_uri)
    if redirect_origin:
        origins.add(redirect_origin.rstrip("/"))
    return origins


def browser_write_allowed(request: Request, settings) -> bool:
    origin = (request.headers.get("origin") or "").rstrip("/")
    if origin not in allowed_browser_origins(settings):
        return False
    provided = (request.headers.get("x-csrf-token") or "").strip()
    cookie = (
        request.cookies.get(browser_cookie_name(CSRF_COOKIE, secure=True))
        or request.cookies.get(browser_cookie_name(CSRF_COOKIE, secure=False))
        or ""
    ).strip()
    if not provided or not cookie or len(provided) > 200 or len(cookie) > 200:
        return False
    return hmac.compare_digest(provided.encode(), cookie.encode())


def _authentication_required() -> JSONResponse:
    return JSONResponse({"detail": "Authentication required"}, status_code=401, headers={"cache-control": "no-store"})


class AuthzMiddleware(BaseHTTPMiddleware):
    async def _api_token(self, request: Request, call_next, path: str, provided: str):
        """A read-only token issued by an administrator (exports, Power BI). Never for writes or owner routes."""
        with SessionLocal() as db:
            info = api_tokens.lookup(db, provided)
            db.commit()
        if info is None:
            return JSONResponse({"detail": "Invalid or revoked API token"}, status_code=401, headers={"cache-control": "no-store"})
        if request.method not in SAFE_METHODS:
            return JSONResponse({"detail": "API tokens are read-only"}, status_code=403)
        if path.startswith(API_TOKEN_BLOCKED_PREFIXES) and path != "/api/v1/auth/token":
            return JSONResponse({"detail": "API tokens cannot use sign-in or owner routes"}, status_code=403)
        request.state.role = "auditor"
        request.state.actor = info["actor"]
        request.state.identity_id = info["identity_id"]
        request.state.tenant_id = info["tenant_id"]
        request.state.api_token = info["token_name"]
        request.state.via_api_token = True
        return await call_next(request)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if request.method == "OPTIONS" or path in PUBLIC_PATHS or any(path.startswith(item) for item in PUBLIC_PREFIXES):
            return await call_next(request)
        settings = get_settings()
        # Network-isolated pilot scrapers may scrape OpenMetrics when explicitly enabled.
        if path == "/api/v1/ops/metrics" and settings.ops_metrics_public and request.method in SAFE_METHODS:
            request.state.role = "auditor"
            request.state.actor = "metrics-scraper"
            return await call_next(request)
        mode = settings.normalized_auth_mode
        provided_token = extract_token(request)
        if mode != "public_demo" and path.startswith("/api/") and api_tokens.looks_like_token(provided_token):
            return await self._api_token(request, call_next, path, provided_token)
        if mode in {"oidc", "local"}:
            opaque = presented_authentication_token(request.cookies, production=settings.is_production)
            if not opaque:
                return _authentication_required()
            with SessionLocal() as db:
                principal = resolve_session(db, opaque)
                db.commit()
            if principal is None:
                if path != "/api/v1/auth/logout":
                    return _authentication_required()
                role = "viewer"
                actor = "signed-out"
            else:
                role = principal.role
                actor = principal.subject
                request.state.identity_id = principal.identity_id
                request.state.tenant_id = principal.tenant_id
        elif mode == "development":
            expected = (settings.api_token or "").strip()
            authenticated = bool(expected) and token_matches(extract_token(request), expected)
            if path.startswith("/api/") and expected and not authenticated:
                return _authentication_required()
            # Cloudflare Access headers are ignored. They do not select the actor or the role.
            if authenticated:
                try:
                    role = canonical_role(settings.api_token_role)
                except ValueError:
                    return JSONResponse({"detail": "Authentication configuration invalid"}, status_code=500)
                actor = settings.api_token_subject.strip()
            else:
                try:
                    role = canonical_role(development_request_role(request))
                except (HTTPException, ValueError) as exc:
                    detail = exc.detail if isinstance(exc, HTTPException) else "Invalid X-Role header"
                    status = exc.status_code if isinstance(exc, HTTPException) else 400
                    return JSONResponse({"detail": detail}, status_code=status)
                actor = (request.headers.get("x-actor") or "operator").strip()
                if not actor or len(actor) > 200:
                    return JSONResponse({"detail": "Invalid X-Actor header"}, status_code=400)
            request.state.development_auth = True
        elif mode == "public_demo":
            if len(request.url.query) > 2000:
                return JSONResponse({"detail": "Query is too large"}, status_code=400)
            length = request.headers.get("content-length")
            if length and length.isdigit() and int(length) > 65536:
                return JSONResponse({"detail": "Request is too large"}, status_code=413)
            if not public_demo_request_allowed(path):
                return JSONResponse(
                    {"detail": "Too many requests"},
                    status_code=429,
                    headers={"Retry-After": "60"},
                )
            actor = settings.public_demo_subject.strip()
            role = "viewer"
            request.state.public_demo = True
        else:
            return JSONResponse({"detail": "Authentication unavailable"}, status_code=503)
        request.state.role = role
        request.state.actor = actor
        if mode in {"oidc", "local"} and request.method not in SAFE_METHODS and not browser_write_allowed(request, settings):
            return JSONResponse({"detail": "Cross-site request blocked"}, status_code=403)
        if (
            path.startswith("/api/")
            and request.method not in SAFE_METHODS
            and path != "/api/v1/auth/logout"
            and not role_may_write(role)
        ):
            return JSONResponse({"detail": "Role is read-only"}, status_code=403)
        return await call_next(request)
