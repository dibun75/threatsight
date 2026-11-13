from __future__ import annotations

import os

from threatsight_api.test_database import drop_isolated_database, provision_isolated_database

USE_LIVE_DB = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}
_ISOLATED_DATABASE: str | None = None
_SERVER_URL: str | None = None

# The flag means "this process can reach PostgreSQL". It does not authorize
# the preserved runtime database. When set, the suite creates a disposable
# database and drops it at session end.
if not USE_LIVE_DB:
    os.environ["THREATSIGHT_RUN_MIGRATIONS"] = "false"
    os.environ["THREATSIGHT_LOG_JSON"] = "false"
    os.environ["THREATSIGHT_DATABASE_URL"] = (
        "postgresql+psycopg://threatsight:invalid@127.0.0.1:1/threatsight_test_offline"
    )
else:
    _SERVER_URL = os.environ.get("THREATSIGHT_DATABASE_URL", "")
    if not _SERVER_URL:
        raise RuntimeError("database tests require a PostgreSQL server URL")
    _ISOLATED_DATABASE, isolated_url = provision_isolated_database(_SERVER_URL)
    os.environ["THREATSIGHT_DATABASE_URL"] = isolated_url
    os.environ["THREATSIGHT_LOG_JSON"] = "false"
    os.environ["THREATSIGHT_RUN_MIGRATIONS"] = "true"

from threatsight_api.config import get_settings  # noqa: E402

get_settings.cache_clear()

_HOSTS_INSTALLED = False


def _install_demo_hosts() -> None:
    """Point demo-agent and demo-site at their Compose addresses when the host has no DNS for them."""
    global _HOSTS_INSTALLED
    import ipaddress
    import socket
    import subprocess

    missing = []
    for name in ("demo-agent", "demo-site"):
        try:
            socket.getaddrinfo(name, None)
        except socket.gaierror:
            missing.append(name)
    if not missing:
        return
    containers = {"demo-agent": "threatsight-demo-agent", "demo-site": "threatsight-demo-site"}
    lines = []
    for name in missing:
        output = subprocess.check_output(
            ["sudo", "docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", containers[name]],
            text=True,
        ).strip()
        address = ipaddress.ip_address(output.split()[0])
        if not address.is_private or str(address) in {"127.0.0.1", "::1"}:
            raise RuntimeError("refusing a demo test address that is not a private container address")
        lines.append(f"{address} {name} # threatsight-test-hosts\n")
    subprocess.run(["sudo", "tee", "-a", "/etc/hosts"], input="".join(lines), text=True, stdout=subprocess.DEVNULL, check=True)
    _HOSTS_INSTALLED = True


def _remove_demo_hosts() -> None:
    if not _HOSTS_INSTALLED:
        return
    import subprocess
    subprocess.check_call(["sudo", "sed", "-i", "/threatsight-test-hosts/d", "/etc/hosts"])


if USE_LIVE_DB:
    _install_demo_hosts()


def pytest_sessionfinish(session, exitstatus) -> None:  # noqa: ARG001
    _remove_demo_hosts()
    if _ISOLATED_DATABASE and _SERVER_URL:
        drop_isolated_database(_SERVER_URL, _ISOLATED_DATABASE)
