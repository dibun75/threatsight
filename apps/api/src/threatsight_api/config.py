from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from threatsight_api.url_safety import endpoint_problem, origin_of

DEPLOYMENT_PROFILES = frozenset({"reference", "pilot-compose", "pilot-kubernetes"})


def _read_secret_file(path: str, *, label: str) -> str:
    cleaned = (path or "").strip()
    if not cleaned:
        return ""
    file_path = Path(cleaned)
    if not file_path.is_file():
        raise ValueError(f"{label} is not a readable file")
    try:
        mode = file_path.stat().st_mode & 0o777
    except OSError as exc:
        raise ValueError(f"{label} is not a readable file") from exc
    # Docker/K8s secret mounts are typically root-owned 0444 under /run/secrets.
    # Host-path secret files outside those mounts must stay owner-readable only.
    resolved = str(file_path.resolve())
    runtime_secret_mount = resolved.startswith(("/run/secrets/", "/var/run/secrets/"))
    if mode & 0o002:
        raise ValueError(f"{label} must not be world-writable")
    if (mode & 0o077) and not runtime_secret_mount:
        raise ValueError(f"{label} must not be group/world-readable")
    value = file_path.read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError(f"{label} is empty")
    if "\x00" in value:
        raise ValueError(f"{label} contains invalid bytes")
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="THREATSIGHT_", extra="ignore")

    env: str = "development"
    deployment_profile: str = "reference"
    public_origin: str = ""
    log_level: str = "INFO"
    log_json: bool = True
    database_url: str = "postgresql+psycopg://threatsight:changeme-dev-only@postgres:5432/threatsight"
    database_url_file: str = ""
    cors_origins: str = "http://localhost:3000"
    web_origins: str = ""
    sandbox_default: bool = True
    kill_switch: bool = False
    run_migrations: bool = True
    allow_synthetic_loaders: bool = True
    product_name: str = "ThreatSight"
    product_version: str = "2.0.0-dev.0"
    milestone: str = "M15"
    evidence_fresh_days: int = 30
    extraction_provider: str = "heuristic"
    intelligence_provider: str = "heuristic"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = "https://api.openai.com/v1"
    max_document_bytes: int = 10_485_760
    assurance_adapter: str = "http"
    demo_agent_url: str = "http://demo-agent:8090"
    discovery_adapter: str = "http"
    demo_site_url: str = "http://demo-site:8091"
    discovery_allowlist: str = ""
    discovery_max_bytes: int = 524_288
    discovery_max_pages: int = 5
    api_token: str = ""
    openapi_enabled: bool = True

    auth_mode: str = "development"

    @field_validator("auth_mode", mode="before")
    @classmethod
    def explicit_auth_mode(cls, value: object) -> str:
        cleaned = str(value or "").strip().lower()
        if cleaned not in {"development", "oidc", "public_demo", "local"}:
            raise ValueError("THREATSIGHT_AUTH_MODE must be development, oidc, public_demo, or local")
        return cleaned
    api_token_subject: str = "web-proxy"
    api_token_role: str = "operator"
    default_workspace_key: str = "default"
    public_demo: bool = False
    public_demo_workspace_key: str = "default"
    public_demo_subject: str = "demo-viewer"
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_client_secret_file: str = ""
    oidc_discovery_url: str = ""
    oidc_authorization_endpoint: str = ""
    oidc_token_endpoint: str = ""
    oidc_jwks_uri: str = ""
    oidc_redirect_uri: str = ""
    oidc_operator_groups: str = ""
    oidc_auditor_groups: str = ""
    oidc_workspace_admin_groups: str = ""
    oidc_platform_admin_groups: str = ""
    auth_session_minutes: int = 480
    auth_idle_minutes: int = 60
    oidc_jit_provisioning: bool = False
    connector_workspace_concurrency: int = 2
    connector_lease_seconds: int = 120
    runner_credential_hours: int = 24
    worker_poll_seconds: float = 2.0
    # Pilot scrapers may scrape /api/v1/ops/metrics when network-isolated; default deny.
    ops_metrics_public: bool = False

    @field_validator("deployment_profile", mode="before")
    @classmethod
    def explicit_deployment_profile(cls, value: object) -> str:
        cleaned = str(value or "reference").strip().lower() or "reference"
        if cleaned not in DEPLOYMENT_PROFILES:
            raise ValueError("THREATSIGHT_DEPLOYMENT_PROFILE must be reference, pilot-compose, or pilot-kubernetes")
        return cleaned

    @model_validator(mode="after")
    def load_secret_files(self) -> "Settings":
        if self.database_url_file.strip():
            object.__setattr__(
                self,
                "database_url",
                _read_secret_file(self.database_url_file, label="THREATSIGHT_DATABASE_URL_FILE"),
            )
        if self.oidc_client_secret_file.strip():
            object.__setattr__(
                self,
                "oidc_client_secret",
                _read_secret_file(self.oidc_client_secret_file, label="THREATSIGHT_OIDC_CLIENT_SECRET_FILE"),
            )
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def web_origin_list(self) -> list[str]:
        return [origin.strip().rstrip("/") for origin in self.web_origins.split(",") if origin.strip()]

    @property
    def is_production(self) -> bool:
        return self.env.strip().lower() == "production"

    @property
    def is_pilot_profile(self) -> bool:
        return self.deployment_profile in {"pilot-compose", "pilot-kubernetes"}

    @property
    def normalized_auth_mode(self) -> str:
        return self.auth_mode.strip().lower()

    def validate_runtime_security(self) -> None:
        problems: list[str] = []
        if self.deployment_profile not in DEPLOYMENT_PROFILES:
            problems.append("THREATSIGHT_DEPLOYMENT_PROFILE is unknown")
        if self.normalized_auth_mode not in {"development", "oidc", "public_demo", "local"}:
            problems.append("THREATSIGHT_AUTH_MODE must be development, oidc, public_demo, or local")
        if self.public_demo and self.normalized_auth_mode != "public_demo":
            problems.append("THREATSIGHT_PUBLIC_DEMO requires THREATSIGHT_AUTH_MODE=public_demo")
        if self.normalized_auth_mode == "public_demo":
            if not self.public_demo:
                problems.append("public_demo requires THREATSIGHT_PUBLIC_DEMO=true")
            if self.is_production:
                problems.append("public_demo cannot run in production")
            if not self.public_demo_workspace_key.strip() or not self.public_demo_subject.strip():
                problems.append("public demo identity is incomplete")
        for origin in self.web_origin_list:
            parsed = urlparse(origin)
            if origin == "*" or parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"}:
                problems.append("THREATSIGHT_WEB_ORIGINS must list explicit http or https origins")
        if not 5 <= self.auth_session_minutes <= 1440:
            problems.append("THREATSIGHT_AUTH_SESSION_MINUTES must be between 5 and 1440")
        if not 5 <= self.auth_idle_minutes <= self.auth_session_minutes:
            problems.append("THREATSIGHT_AUTH_IDLE_MINUTES must be between 5 minutes and the session lifetime")
        if not 1 <= self.connector_workspace_concurrency <= 20:
            problems.append("THREATSIGHT_CONNECTOR_WORKSPACE_CONCURRENCY must be between 1 and 20")
        if not 30 <= self.connector_lease_seconds <= 3600:
            problems.append("THREATSIGHT_CONNECTOR_LEASE_SECONDS must be between 30 and 3600")
        if not 1 <= self.runner_credential_hours <= 168:
            problems.append("THREATSIGHT_RUNNER_CREDENTIAL_HOURS must be between 1 and 168")
        if not self.is_production:
            if problems:
                raise ValueError("Unsafe runtime configuration: " + "; ".join(problems))
            return
        if self.normalized_auth_mode not in {"local", "oidc"}:
            problems.append("production requires THREATSIGHT_AUTH_MODE=local or oidc")
        if self.is_pilot_profile and self.normalized_auth_mode not in {"oidc", "local"}:
            problems.append("pilot profiles require THREATSIGHT_AUTH_MODE=oidc (or local break-glass only)")
        if self.is_pilot_profile:
            origin = self.public_origin.strip().rstrip("/")
            if not origin:
                problems.append("THREATSIGHT_PUBLIC_ORIGIN is required for production pilot profiles")
            else:
                parsed = urlparse(origin)
                if parsed.scheme != "https" or not parsed.netloc or parsed.path not in {"", "/"}:
                    problems.append("THREATSIGHT_PUBLIC_ORIGIN must be an https origin without a path")
                if origin not in {item.rstrip("/") for item in self.cors_origin_list}:
                    problems.append("THREATSIGHT_PUBLIC_ORIGIN must be listed in THREATSIGHT_CORS_ORIGINS")
            if not self.web_origin_list:
                problems.append("THREATSIGHT_WEB_ORIGINS is required for production pilot profiles")
        if self.deployment_profile == "pilot-kubernetes":
            host = urlparse(self.database_url).hostname or ""
            if host in {"", "postgres", "localhost", "127.0.0.1"}:
                problems.append(
                    "pilot-kubernetes requires an external PostgreSQL URL (bundled postgres hostname is not accepted)"
                )
        if self.normalized_auth_mode == "oidc":
            for name, value in (
                ("THREATSIGHT_OIDC_ISSUER", self.oidc_issuer),
                ("THREATSIGHT_OIDC_AUDIENCE", self.oidc_audience),
                ("THREATSIGHT_OIDC_CLIENT_ID", self.oidc_client_id),
                ("THREATSIGHT_OIDC_AUTHORIZATION_ENDPOINT", self.oidc_authorization_endpoint),
                ("THREATSIGHT_OIDC_TOKEN_ENDPOINT", self.oidc_token_endpoint),
                ("THREATSIGHT_OIDC_JWKS_URI", self.oidc_jwks_uri),
                ("THREATSIGHT_OIDC_REDIRECT_URI", self.oidc_redirect_uri),
            ):
                if not value.strip():
                    problems.append(f"{name} is required")
                elif name not in {"THREATSIGHT_OIDC_AUDIENCE", "THREATSIGHT_OIDC_CLIENT_ID"}:
                    problem = endpoint_problem(value)
                    if problem:
                        problems.append(f"{name} {problem}")
        if "changeme-dev-only" in self.database_url:
            problems.append("the development database password is forbidden")
        origins = self.cors_origin_list
        if not origins or "*" in origins:
            problems.append("THREATSIGHT_CORS_ORIGINS must be an explicit allow-list")
        for origin in origins:
            parsed = urlparse(origin)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                problems.append(f"invalid CORS origin: {origin}")
        if self.normalized_auth_mode == "oidc":
            redirect_origin = origin_of(self.oidc_redirect_uri)
            if redirect_origin and redirect_origin not in {item.rstrip("/") for item in origins}:
                problems.append("THREATSIGHT_OIDC_REDIRECT_URI origin must match THREATSIGHT_CORS_ORIGINS")
        if not self.sandbox_default:
            problems.append("THREATSIGHT_SANDBOX_DEFAULT must remain enabled")
        if self.openapi_enabled:
            problems.append("OpenAPI documentation must be disabled in production")
        if problems:
            raise ValueError("Unsafe production configuration: " + "; ".join(problems))

@lru_cache
def base_settings() -> Settings:
    """Settings from the environment only. Used to start the database engine."""
    return Settings()


def get_settings() -> Settings:
    """Environment settings with the values an administrator saved on the Settings page.

    Saved values are read from the database only once something has configured the engine, and are
    cached for a few seconds, so this stays cheap and never connects on its own.
    """
    from threatsight_api import runtime_settings

    return runtime_settings.merge(base_settings(), runtime_settings.overrides())


def _clear_settings_cache() -> None:
    from threatsight_api import runtime_settings

    base_settings.cache_clear()
    runtime_settings.clear_cache()


get_settings.cache_clear = _clear_settings_cache  # type: ignore[attr-defined]
