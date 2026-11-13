#!/usr/bin/env python3
"""Validate ThreatSight configuration without printing secret values."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

SECRET_SUFFIXES = ("_SECRET", "_PASSWORD", "_TOKEN", "_KEY", "_CREDENTIAL")
SECRET_NAMES = {
    "THREATSIGHT_DATABASE_URL",
    "THREATSIGHT_OIDC_CLIENT_SECRET",
    "THREATSIGHT_API_TOKEN",
}


def _load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'").strip('"')
    return values


def _redact(key: str, value: str) -> str:
    if key in SECRET_NAMES or key.endswith(SECRET_SUFFIXES) or key.endswith("_FILE"):
        return "<redacted>" if value else "<empty>"
    if "://" in value and "@" in value:
        return "<redacted-url>"
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, help="Optional dotenv file to load before validation")
    parser.add_argument("--profile", default="", help="Override THREATSIGHT_DEPLOYMENT_PROFILE")
    args = parser.parse_args()

    if args.env_file:
        if not args.env_file.is_file():
            print(f"FAIL env-file missing: {args.env_file}", file=sys.stderr)
            return 2
        for key, value in _load_env_file(args.env_file).items():
            os.environ.setdefault(key, value)

    if args.profile:
        os.environ["THREATSIGHT_DEPLOYMENT_PROFILE"] = args.profile

    # Ensure package import when run from repo root.
    repo = Path(__file__).resolve().parents[2]
    api_src = repo / "apps" / "api" / "src"
    if str(api_src) not in sys.path:
        sys.path.insert(0, str(api_src))

    from threatsight_api.config import Settings, get_settings

    get_settings.cache_clear()
    try:
        settings = Settings()
        settings.validate_runtime_security()
    except Exception as exc:  # noqa: BLE001 — CLI surface
        print(f"FAIL {exc}")
        return 1

    safe_rows = [
        ("env", settings.env),
        ("deployment_profile", settings.deployment_profile),
        ("auth_mode", settings.auth_mode),
        ("public_origin", settings.public_origin or "<unset>"),
        ("cors_origins", settings.cors_origins),
        ("openapi_enabled", str(settings.openapi_enabled)),
        ("sandbox_default", str(settings.sandbox_default)),
        ("allow_synthetic_loaders", str(settings.allow_synthetic_loaders)),
        ("database_url", _redact("THREATSIGHT_DATABASE_URL", settings.database_url)),
        ("oidc_issuer", settings.oidc_issuer or "<unset>"),
        ("oidc_client_id", settings.oidc_client_id or "<unset>"),
        ("oidc_client_secret", _redact("THREATSIGHT_OIDC_CLIENT_SECRET", settings.oidc_client_secret)),
    ]
    print("PASS configuration validates")
    for key, value in safe_rows:
        print(f"  {key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
