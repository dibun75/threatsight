#!/usr/bin/env python3
"""ThreatSight Docker host helper.

Allocates free host ports, starts only this project's Compose stack, and
restricts cleanup to exact, labelled current-generation resources.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from pathlib import Path

PROJECT = "threatsight"
PREFERRED_PORTS = {
    "WEB_PORT": 3000,
    "API_PORT": 8000,
    "POSTGRES_PORT": 5432,
}
CONTAINER_PORT_TO_ENV = {
    "3000": "WEB_PORT",
    "8000": "API_PORT",
    "5432": "POSTGRES_PORT",
}
ALLOWED_IMAGE_REPOS = (
    "threatsight-api",
    "threatsight-web",
    "threatsight-demo-agent",
    "threatsight-demo-site",
    "threatsight-postgres",
)
ALLOWED_CONTAINERS = frozenset(
    {
        "threatsight-api",
        "threatsight-web",
        "threatsight-postgres",
        "threatsight-demo-agent",
        "threatsight-demo-site",
        "threatsight-migrate",
    }
)
ALLOWED_VOLUME = "threatsight_postgres_data"
ALLOWED_NETWORK = "threatsight_default"
FORBIDDEN_NAME_FRAGMENTS = (
    "portainer",
    "infra-",
    "infra_",
    "caddy",
    "cloudflared",
)
PORT_LINE = re.compile(
    r"(?:0\.0\.0\.0|\[::\]):(?P<host>\d+)->(?P<container>\d+)",
)
ROOT = Path(__file__).resolve().parents[1]
RUNTIME_PORTS = ROOT / ".runtime-ports"
TUNNEL_COMPOSE = ROOT / "docker-compose.tunnel.yml"
DEPLOY_ENV = ROOT / ".deploy.env"
# The full single-host live stack: base file plus these overlays, in this order. Plain `make up` loads only the
# base file, which recreates web without the tunnel network and takes the public site down.
LIVE_OVERLAYS = ("tunnel", "signing", "threatfox", "abusech", "vulncheck", "telemetry")
# Host secret files each overlay bind-mounts. Deploy refuses to start if one is unset or missing.
OVERLAY_SECRET_PATHS = {
    "signing": ("THREATSIGHT_EVIDENCE_SIGNING_KEY_PATH",),
    "threatfox": ("THREATSIGHT_THREATFOX_AUTH_KEY_PATH",),
    "abusech": ("THREATSIGHT_ABUSECH_AUTH_KEY_PATH",),
    "vulncheck": ("THREATSIGHT_VULNCHECK_TOKEN_PATH",),
    "telemetry": ("THREATSIGHT_RADAR_TOKEN_PATH",),
}
# Deploy never rebuilds these: the signer runs a pinned merge-SHA image (docs/reference/runbooks/evidence-signing.md).
DEPLOY_NO_BUILD_SERVICES = frozenset({"evidence-signer"})


class UnsafeCleanupError(RuntimeError):
    pass


def run_docker(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sudo", "docker", *args],
        check=check,
        capture_output=True,
        text=True,
    )


def load_profile() -> str:
    if not RUNTIME_PORTS.is_file():
        return "lab"
    for line in RUNTIME_PORTS.read_text().splitlines():
        if line.startswith("COMPOSE_PROFILE="):
            value = line.split("=", 1)[1].strip()
            return value or "lab"
    return "lab"


def compose_command(
    *args: str,
    enterprise: bool | None = None,
    tunnel: bool = False,
) -> list[str]:
    command = ["sudo", "docker", "compose", "-p", PROJECT, "-f", str(ROOT / "docker-compose.yml")]
    use_enterprise = load_profile() == "enterprise" if enterprise is None else enterprise
    if use_enterprise:
        command.extend(["-f", str(ROOT / "docker-compose.enterprise.yml")])
    if tunnel:
        command.extend(["-f", str(TUNNEL_COMPOSE)])
    env_path = ROOT / ".env"
    if env_path.is_file():
        command.extend(["--env-file", str(env_path)])
    if RUNTIME_PORTS.is_file():
        command.extend(["--env-file", str(RUNTIME_PORTS)])
    command.extend(args)
    return command


def read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.removeprefix("export ").strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key] = value
    return values


def deploy_overlays(env: dict[str, str]) -> tuple[str, ...]:
    raw = env.get("THREATSIGHT_DEPLOY_OVERLAYS", "").strip()
    if not raw:
        return LIVE_OVERLAYS
    overlays = tuple(item for item in re.split(r"[\s,]+", raw) if item)
    for overlay in overlays:
        if not (ROOT / f"docker-compose.{overlay}.yml").is_file():
            raise SystemExit(f"Unknown overlay in THREATSIGHT_DEPLOY_OVERLAYS: {overlay}")
    return overlays


def deploy_compose_command(
    *args: str,
    overlays: Iterable[str],
    image_tag: str,
    deploy_env: Path = DEPLOY_ENV,
) -> list[str]:
    # `sudo env` so the tag reaches compose whatever sudoers allows; compose prefers the shell
    # environment over --env-file, so this tag wins over any value in .env.
    command = [
        "sudo", "env", f"THREATSIGHT_IMAGE_TAG={image_tag}",
        "docker", "compose", "-p", PROJECT, "-f", str(ROOT / "docker-compose.yml"),
    ]
    for overlay in overlays:
        command.extend(["-f", str(ROOT / f"docker-compose.{overlay}.yml")])
    for env_path in (ROOT / ".env", RUNTIME_PORTS, deploy_env):
        if env_path.is_file():
            command.extend(["--env-file", str(env_path)])
    command.extend(args)
    return command


def missing_deploy_secrets(env: dict[str, str], overlays: Iterable[str]) -> list[str]:
    problems = []
    for overlay in overlays:
        for key in OVERLAY_SECRET_PATHS.get(overlay, ()):
            path = env.get(key, "")
            if not path:
                problems.append(f"{key} is not set (needed by docker-compose.{overlay}.yml)")
            elif subprocess.run(["sudo", "test", "-f", path], check=False).returncode:
                problems.append(f"{key}={path} does not exist")
    return problems


def git_head() -> tuple[str, bool]:
    sha = subprocess.run(
        ["git", "rev-parse", "--short=7", "HEAD"], check=True, capture_output=True, text=True, cwd=ROOT
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            check=True,
            capture_output=True,
            text=True,
            cwd=ROOT,
        ).stdout.strip()
    )
    return sha, dirty


PS_HEALTH_FORMAT = "{{.Service}}\t{{.State}}\t{{.Health}}"


def all_services_ready(ps_output: str) -> bool:
    """True when every service is running and healthy, or running with no healthcheck (e.g. worker)."""
    rows = [line.split("\t") for line in ps_output.splitlines() if line.strip()]
    if not rows:
        return False
    for row in rows:
        state = row[1].strip() if len(row) > 1 else ""
        health = row[2].strip() if len(row) > 2 else ""
        if state != "running" or health not in ("healthy", ""):
            return False
    return True


def run_step(label: str, command: list[str], *, env: dict[str, str] | None = None, **kwargs) -> None:
    print(f"==> {label}", flush=True)
    subprocess.run(command, check=True, cwd=ROOT, env=env, **kwargs)


def cmd_deploy(
    *, allow_dirty: bool, skip_backup: bool, skip_build: bool = False, deploy_env: Path = DEPLOY_ENV
) -> None:
    """Build, start and migrate the full live stack, with every overlay the public site needs."""
    if not deploy_env.is_file():
        raise SystemExit(
            f"{deploy_env} not found. Copy deploy/live.env.example to .deploy.env and fill in the host paths."
        )
    env_values = read_env_file(deploy_env)
    overlays = deploy_overlays(env_values)
    sha, dirty = git_head()
    if dirty and not allow_dirty:
        raise SystemExit("Working tree has uncommitted changes; image tags would not match the code. Commit first or pass --allow-dirty.")
    problems = missing_deploy_secrets(env_values, overlays)
    if problems:
        raise SystemExit("Deploy preflight failed:\n  " + "\n  ".join(problems))

    # Every locally built image is tagged with the commit it was built from (see docker-compose.yml).
    # A THREATSIGHT_IMAGE_TAG in .deploy.env overrides it, for rolling back to an older build.
    tag = env_values.get("THREATSIGHT_IMAGE_TAG") or sha

    def compose(*args: str) -> list[str]:
        return deploy_compose_command(*args, overlays=overlays, image_tag=tag, deploy_env=deploy_env)

    print(f"deploy commit {sha} (image tag {tag}); overlays: {', '.join(overlays)}", flush=True)
    run_step("validate compose config", compose("config", "--quiet"))

    if not skip_backup:
        dest_dir = ROOT / "backups"
        dest_dir.mkdir(exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        dest = dest_dir / f"threatsight-predeploy-{stamp}.dump"
        with dest.open("wb") as output:
            run_step(
                f"database backup -> {dest.relative_to(ROOT)}",
                compose(
                    "exec", "-T", "postgres", "pg_dump", "-U", "threatsight", "-d", "threatsight",
                    "--format=custom", "--no-owner", "--no-privileges",
                ),
                stdout=output,
            )

    services = subprocess.run(
        compose("config", "--services"), check=True, capture_output=True, text=True, cwd=ROOT
    ).stdout.split()
    to_build = [service for service in services if service not in DEPLOY_NO_BUILD_SERVICES]
    if not skip_build:
        run_step(f"build {' '.join(to_build)}", compose("build", *to_build))
    run_step("start the stack", compose("up", "-d", "--no-build"))
    run_step("run database migrations", compose("exec", "-T", "api", "alembic", "upgrade", "head"))

    print("==> wait for healthy services", flush=True)
    deadline = time.time() + 600
    while True:
        result = subprocess.run(
            compose("ps", "--format", PS_HEALTH_FORMAT), check=False, capture_output=True, text=True, cwd=ROOT
        )
        if all_services_ready(result.stdout):
            break
        if time.time() > deadline:
            raise SystemExit("Services did not become healthy in time.\n" + result.stdout)
        time.sleep(5)
    subprocess.run(compose("ps"), check=False, cwd=ROOT)
    print(
        f"deployed {sha} as image tag {tag}. To roll back, set THREATSIGHT_IMAGE_TAG=<previous tag> in .deploy.env "
        "and run `make deploy ARGS=--skip-build`; restore the predeploy dump if a migration must be undone."
    )


def run_compose(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        compose_command(*args),
        check=check,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def docker_ps_rows() -> list[dict[str, str]]:
    fmt = (
        "{{.ID}}\t{{.Names}}\t{{.Label \"com.docker.compose.project\"}}"
        "\t{{.Label \"com.threatsight.generation\"}}\t{{.Ports}}\t{{.Status}}"
    )
    result = run_docker(["ps", "-a", "--format", fmt])
    rows: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        rows.append(
            {
                "id": parts[0],
                "name": parts[1],
                "project": parts[2],
                "generation": parts[3],
                "ports": parts[4],
                "status": parts[5],
            }
        )
    return rows


def published_ports_by_env() -> dict[str, int]:
    found: dict[str, int] = {}
    for row in docker_ps_rows():
        if not is_threatsight_resource(row["name"], row["project"], row["generation"]):
            continue
        for match in PORT_LINE.finditer(row["ports"]):
            env_name = CONTAINER_PORT_TO_ENV.get(match.group("container"))
            if env_name:
                found[env_name] = int(match.group("host"))
    return found


def docker_host_port_owners(rows: list[dict[str, str]] | None = None) -> dict[int, str]:
    owners: dict[int, str] = {}
    for row in rows if rows is not None else docker_ps_rows():
        for match in PORT_LINE.finditer(row["ports"]):
            owners[int(match.group("host"))] = row["name"]
    return owners


def tcp_port_bindable(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError:
            return False
    return True


def load_runtime_ports() -> dict[str, int]:
    values: dict[str, int] = {}
    if not RUNTIME_PORTS.is_file():
        return values
    for line in RUNTIME_PORTS.read_text().splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw = line.split("=", 1)
        if key in PREFERRED_PORTS:
            values[key] = int(raw.strip())
    return values


def is_threatsight_resource(name: str, project: str = "", generation: str = "") -> bool:
    if any(fragment in name.lower() for fragment in FORBIDDEN_NAME_FRAGMENTS):
        return False
    return project == PROJECT and generation == "current" and name in ALLOWED_CONTAINERS


def our_container_names(rows: list[dict[str, str]] | None = None) -> set[str]:
    names: set[str] = set()
    for row in rows if rows is not None else docker_ps_rows():
        if is_threatsight_resource(row["name"], row["project"], row["generation"]):
            names.add(row["name"])
    return names


def port_is_usable(
    port: int,
    *,
    owners: dict[int, str],
    our_names: set[str],
) -> bool:
    owner = owners.get(port)
    if owner:
        return owner in our_names
    return tcp_port_bindable(port)


def next_free_port(
    preferred: int,
    *,
    occupied: Iterable[int] = (),
    owners: dict[int, str] | None = None,
    our_names: set[str] | None = None,
) -> int:
    taken = set(occupied)
    rows = None
    if owners is None or our_names is None:
        rows = docker_ps_rows()
    resolved_owners = owners if owners is not None else docker_host_port_owners(rows)
    resolved_ours = our_names if our_names is not None else our_container_names(rows)
    for port in range(preferred, preferred + 100):
        if port in taken:
            continue
        if port_is_usable(port, owners=resolved_owners, our_names=resolved_ours):
            return port
    raise RuntimeError(f"No free host port found near {preferred}")


def allocate_ports() -> dict[str, int]:
    rows = docker_ps_rows()
    existing = published_ports_by_env()
    previous = load_runtime_ports()
    owners = docker_host_port_owners(rows)
    our_names = our_container_names(rows)
    chosen: dict[str, int] = {}
    for key, preferred in PREFERRED_PORTS.items():
        if key in existing:
            chosen[key] = existing[key]
            continue
        candidate = previous.get(key, preferred)
        if (
            candidate not in chosen.values()
            and port_is_usable(candidate, owners=owners, our_names=our_names)
        ):
            chosen[key] = candidate
            continue
        chosen[key] = next_free_port(
            preferred,
            occupied=chosen.values(),
            owners=owners,
            our_names=our_names,
        )
    return chosen


def write_runtime_ports(ports: dict[str, int], profile: str = "lab") -> None:
    web = ports["WEB_PORT"]
    contents = "\n".join(
        [
            "# Generated by scripts/threatsight_docker.py. Do not commit.",
            f"# Preferred: web={PREFERRED_PORTS['WEB_PORT']} "
            f"api={PREFERRED_PORTS['API_PORT']} postgres={PREFERRED_PORTS['POSTGRES_PORT']}",
            f"POSTGRES_PORT={ports['POSTGRES_PORT']}",
            f"API_PORT={ports['API_PORT']}",
            f"WEB_PORT={web}",
            f"THREATSIGHT_CORS_ORIGINS=http://localhost:{web}",
            f"COMPOSE_PROFILE={profile}",
            "",
        ]
    )
    RUNTIME_PORTS.write_text(contents)


def allocate_and_persist(profile: str = "lab") -> dict[str, int]:
    ports = allocate_ports()
    write_runtime_ports(ports, profile=profile)
    return ports


def print_ports(ports: dict[str, int]) -> None:
    print("ThreatSight host ports:", flush=True)
    print(f"  web      http://localhost:{ports['WEB_PORT']}", flush=True)
    print(f"  api      http://localhost:{ports['API_PORT']}", flush=True)
    print(f"  postgres localhost:{ports['POSTGRES_PORT']}", flush=True)
    print(f"  recorded {RUNTIME_PORTS}", flush=True)


def cmd_inspect() -> None:
    print("=== docker ps -a ===")
    sys.stdout.write(run_docker(["ps", "-a"]).stdout)
    print("=== docker images ===")
    sys.stdout.write(run_docker(["images"]).stdout)
    print("=== docker volume ls ===")
    sys.stdout.write(run_docker(["volume", "ls"]).stdout)
    print("=== docker network ls ===")
    sys.stdout.write(run_docker(["network", "ls"]).stdout)
    print("=== ThreatSight labelled containers ===")
    labelled = run_docker(
        [
            "ps",
            "-a",
            "--filter",
            "label=com.threatsight.project=threatsight",
            "--format",
            "{{.Names}} {{.Status}}",
        ]
    )
    sys.stdout.write(labelled.stdout or "(none)\n")
    print("=== ThreatSight current generation owned ===")
    for item in owned_inventory():
        print(f"  {item}")


def owned_inventory(*, include_volume: bool = True) -> list[str]:
    items: list[str] = []
    for row in docker_ps_rows():
        if is_threatsight_resource(row["name"], row["project"], row["generation"]):
            items.append(f"container {row['name']}")
    images = run_docker(["images", "--format", "{{.Repository}}:{{.Tag}}"]).stdout.splitlines()
    for image in images:
        repo = image.split(":", 1)[0]
        if repo in ALLOWED_IMAGE_REPOS:
            items.append(f"image {image}")
    volumes = run_docker(["volume", "ls", "--format", "{{.Name}}"]).stdout.splitlines()
    if include_volume:
        for volume in volumes:
            if volume == ALLOWED_VOLUME:
                items.append(f"volume {volume}")
    networks = run_docker(["network", "ls", "--format", "{{.Name}}"]).stdout.splitlines()
    for network in networks:
        if network == ALLOWED_NETWORK:
            items.append(f"network {network}")
    return items


def assert_cleanup_target(kind: str, name: str) -> None:
    if any(fragment in name.lower() for fragment in FORBIDDEN_NAME_FRAGMENTS):
        raise UnsafeCleanupError(f"Refusing to touch {kind} '{name}'")
    allowed = False
    if kind == "container":
        allowed = name in ALLOWED_CONTAINERS
    elif kind == "image":
        allowed = name.split(":", 1)[0] in ALLOWED_IMAGE_REPOS
    elif kind == "volume":
        allowed = name == ALLOWED_VOLUME
    elif kind == "network":
        allowed = name == ALLOWED_NETWORK
    if not allowed:
        raise UnsafeCleanupError(f"Refusing to touch {kind} '{name}'")


def assert_no_unknown_project_containers(rows: list[dict[str, str]]) -> None:
    for row in rows:
        if row["project"] != PROJECT:
            continue
        if not is_threatsight_resource(row["name"], row["project"], row["generation"]):
            raise UnsafeCleanupError(
                f"Refusing cleanup: unknown or unlabelled project container '{row['name']}'"
            )


def cmd_clean(*, volumes: bool, dry_run: bool) -> None:
    cmd_inspect()
    targets: list[tuple[str, str]] = []
    rows = docker_ps_rows()
    assert_no_unknown_project_containers(rows)
    for row in rows:
        if is_threatsight_resource(row["name"], row["project"], row["generation"]):
            targets.append(("container", row["name"]))
    for image in run_docker(["images", "--format", "{{.Repository}}:{{.Tag}}"]).stdout.splitlines():
        if image.split(":", 1)[0] in ALLOWED_IMAGE_REPOS:
            targets.append(("image", image))
    if volumes:
        for volume in run_docker(["volume", "ls", "--format", "{{.Name}}"]).stdout.splitlines():
            if volume == ALLOWED_VOLUME:
                targets.append(("volume", volume))
    for network in run_docker(["network", "ls", "--format", "{{.Name}}"]).stdout.splitlines():
        if network == ALLOWED_NETWORK:
            targets.append(("network", network))

    for kind, name in targets:
        assert_cleanup_target(kind, name)

    print("=== cleanup targets (current ThreatSight project only) ===")
    if not targets:
        print("  (none)")
        return
    for kind, name in targets:
        print(f"  {kind} {name}")
    if dry_run:
        print("Dry run: nothing removed.")
        return

    down_args = ["down"]
    if volumes:
        down_args.append("--volumes")
        print("WARNING: removing the current ThreatSight postgres volume only.")
    down = run_compose(down_args)
    if down.stdout:
        sys.stdout.write(down.stdout)
    if down.stderr:
        sys.stderr.write(down.stderr)

    remaining_images = [
        image
        for image in run_docker(["images", "--format", "{{.Repository}}:{{.Tag}}"]).stdout.splitlines()
        if image.split(":", 1)[0] in ALLOWED_IMAGE_REPOS
    ]
    for image in remaining_images:
        assert_cleanup_target("image", image)
        run_docker(["rmi", image], check=False)


def wait_healthy(timeout_s: int = 90) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        result = run_compose(["ps", "--format", PS_HEALTH_FORMAT], check=False)
        if all_services_ready(result.stdout):
            return
        time.sleep(2)
    raise SystemExit("Services did not become healthy in time.\n" + run_compose(["ps"]).stdout)


def cmd_up(*, build: bool, enterprise: bool = False, tunnel: bool = False) -> None:
    ports = allocate_and_persist(profile="enterprise" if enterprise else "lab")
    print_ports(ports)
    if enterprise:
        print("profile enterprise (no demo sidecars, postgres unpublished)", flush=True)
    args = ["up", "-d"]
    if build:
        args.append("--build")
    result = subprocess.run(
        compose_command(*args, enterprise=enterprise, tunnel=tunnel),
        check=True,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    wait_healthy()
    cmd_ps()
    cmd_smoke()


def cmd_down() -> None:
    result = run_compose(["down"])
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)


def cmd_ps() -> None:
    result = run_compose(["ps"])
    sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)


def cmd_restart() -> None:
    result = run_compose(["restart"])
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    wait_healthy()


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read().decode()


def cmd_smoke() -> None:
    ports = load_runtime_ports() or allocate_and_persist()
    api = ports["API_PORT"]
    web = ports["WEB_PORT"]
    checks = {
        f"http://localhost:{api}/health": '"status":"ok"',
        f"http://localhost:{api}/ready": '"status":"ok"',
        f"http://localhost:{api}/api/v1/meta": '"milestone":"M15"',
        f"http://localhost:{api}/api/v1/security/status": '"llm_authors_executive_summary":false',
        f"http://localhost:{api}/api/v1/dashboard": '"legal_compliance_claim":false',
        f"http://localhost:{api}/api/v1/assurance/status": '"evaluator":"deterministic_policy"',
        f"http://localhost:{api}/api/v1/discovery/status": '"unrestricted_crawl":false',
        f"http://localhost:{api}/api/v1/frameworks/status": '"legal_compliance_claim":false',
        f"http://localhost:{api}/api/v1/threats/status": '"autonomous_attack":false',
        f"http://localhost:{api}/api/v1/intelligence/status": '"llm_is_verdict_authority":false',
        f"http://localhost:{api}/api/v1/connectivity/status": '"runtime_firewall":false',
        f"http://localhost:{api}/api/v1/ops/status": '"legal_compliance_claim":false',
        f"http://localhost:{api}/api/v1/showcase/status": '"llm_authors_executive_summary":false',
        f"http://localhost:{api}/api/v1/exports/control-matrix.json": '"legal_compliance_claim":false',
    }
    for url, needle in checks.items():
        body = fetch(url)
        if needle not in body:
            raise SystemExit(f"Unexpected response from {url}: {body}")
        print(f"ok {url}")
    for path in ("/", "/showcase", "/systems", "/controls", "/frameworks", "/threats", "/findings", "/evidence", "/documents", "/assurance", "/discovery", "/ops", "/audit", "/exports", "/exposure", "/lab", "/reports"):
        try:
            urllib.request.urlopen(f"http://localhost:{web}{path}", timeout=5)
        except urllib.error.URLError as exc:
            raise SystemExit(f"Web origin failed for {path}: {exc}") from exc
        print(f"ok http://localhost:{web}{path}")
    print("ok docker compose ps")
    cmd_ps()


def cmd_ports() -> None:
    if RUNTIME_PORTS.is_file():
        sys.stdout.write(RUNTIME_PORTS.read_text())
    else:
        print("No .runtime-ports yet. Run: make up")
    existing = published_ports_by_env()
    if existing:
        print("Published ThreatSight ports:")
        for key, value in existing.items():
            print(f"  {key}={value}")


def cmd_backup() -> None:
    dest_dir = ROOT / "backups"
    dest_dir.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    dest = dest_dir / f"threatsight-{stamp}.dump"
    command = compose_command(
        "exec",
        "-T",
        "postgres",
        "pg_dump",
        "-U",
        "threatsight",
        "-d",
        "threatsight",
        "--format=custom",
        "--no-owner",
        "--no-privileges",
    )
    with dest.open("wb") as output:
        subprocess.run(command, check=True, stdout=output, cwd=ROOT)
    with dest.with_suffix(".dump.sha256").open("w") as checksum:
        subprocess.run(["sha256sum", str(dest)], check=True, stdout=checksum)
    with dest.with_suffix(".dump.manifest").open("w") as manifest:
        subprocess.run(["pg_restore", "--list", str(dest)], check=True, stdout=manifest)
    print(dest)


def cmd_restore(path: str, *, yes: bool) -> None:
    if not yes:
        raise SystemExit("Restore replaces the ThreatSight database. Re-run with --yes.")
    sql_path = Path(path)
    if not sql_path.is_file():
        raise SystemExit(f"Backup not found: {sql_path}")
    checksum_path = Path(f"{sql_path}.sha256")
    if not checksum_path.is_file():
        raise SystemExit(f"Backup checksum not found: {checksum_path}")
    expected = checksum_path.read_text().split()[0]
    digest = hashlib.sha256()
    with sql_path.open("rb") as archive:
        for chunk in iter(lambda: archive.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise SystemExit("Backup checksum mismatch")
    archive_check = subprocess.run(
        ["pg_restore", "--list", str(sql_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if archive_check.returncode:
        raise SystemExit("Backup is not a valid pg_restore archive")
    rows = docker_ps_rows()
    target = next((row for row in rows if row["name"] == "threatsight-postgres"), None)
    if target is None or not is_threatsight_resource(
        target["name"], target["project"], target["generation"]
    ):
        raise SystemExit("Restore target is not the labelled current ThreatSight database")
    result = subprocess.run(
        compose_command(
            "exec",
            "-T",
            "postgres",
            "pg_restore",
            "-U",
            "threatsight",
            "-d",
            "threatsight",
            "--clean",
            "--if-exists",
            "--no-owner",
            "--no-privileges",
            "--exit-on-error",
            "--single-transaction",
        ),
        check=False,
        capture_output=True,
        cwd=ROOT,
        input=sql_path.read_bytes(),
    )
    sys.stdout.write(result.stdout.decode())
    if result.stderr:
        sys.stderr.write(result.stderr.decode())
    if result.returncode:
        raise SystemExit(result.returncode)
    print("restore complete")


def cmd_test() -> None:
    """Run the workspace suite against a disposable database.

    Sources are staged under /tmp inside the API container and imported via
    PYTHONPATH. The running server keeps its installed package. The test
    process still receives THREATSIGHT_TEST_USE_LIVE_DB so it can reach
    PostgreSQL; conftest then refuses the preserved ``threatsight`` database.
    """
    stage = "/tmp/ts-pytest"
    run_compose(["exec", "-T", "-u", "0", "api", "rm", "-rf", stage])
    run_compose(["exec", "-T", "-u", "0", "api", "mkdir", "-p", stage])
    run_compose(["cp", str(ROOT / "apps/api/src/threatsight_api"), f"api:{stage}/threatsight_api"])
    run_compose(["cp", str(ROOT / "apps/api/tests"), f"api:{stage}/tests"])
    run_compose(["cp", str(ROOT / "apps/api/alembic.ini"), f"api:{stage}/alembic.ini"])
    run_compose(["cp", str(ROOT / "apps/api/alembic"), f"api:{stage}/alembic"])
    run_compose(["exec", "-T", "-u", "0", "api", "chmod", "-R", "a+rX", stage])
    result = run_compose(
        [
            "exec",
            "-T",
            "-e",
            f"PYTHONPATH={stage}",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            "-e",
            "THREATSIGHT_TEST_USE_LIVE_DB=true",
            "-w",
            stage,
            "api",
            "python",
            "-m",
            "pytest",
            "tests",
            "-q",
            "-p",
            "no:cacheprovider",
        ],
        check=False,
    )
    sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    if result.returncode:
        raise SystemExit(result.returncode)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ThreatSight Docker host helper")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("allocate", help="Choose free host ports and write .runtime-ports")
    up = sub.add_parser("up", help="Allocate ports and start the ThreatSight stack")
    up.add_argument("--build", action="store_true")
    up.add_argument("--enterprise", action="store_true", help="Production-like overlay: no demo sidecars, unpublished Postgres")
    up.add_argument("--tunnel", action="store_true", help="Attach web to the optional infra_gateway network")
    sub.add_parser("down", help="Stop ThreatSight containers; keep the database volume")
    sub.add_parser("restart", help="Restart ThreatSight services")
    sub.add_parser("ps", help="Show ThreatSight compose status")
    sub.add_parser("ports", help="Show allocated and published host ports")
    sub.add_parser("inspect", help="Read-only host and ThreatSight inventory")
    sub.add_parser("smoke", help="Verify health endpoints and compose ps")
    sub.add_parser("test", help="Run API tests inside the ThreatSight api container")
    sub.add_parser("backup", help="Dump Postgres into backups/")
    deploy = sub.add_parser("deploy", help="Back up, build, start and migrate the full live stack (all overlays)")
    deploy.add_argument("--allow-dirty", action="store_true", help="Deploy with uncommitted changes")
    deploy.add_argument("--skip-backup", action="store_true", help="Skip the predeploy pg_dump")
    deploy.add_argument("--skip-build", action="store_true", help="Start existing images for THREATSIGHT_IMAGE_TAG (rollback)")
    restore = sub.add_parser("restore", help="Restore Postgres from a SQL dump (destructive)")
    restore.add_argument("path")
    restore.add_argument("--yes", action="store_true")
    clean = sub.add_parser("clean", help="Remove current ThreatSight resources only")
    clean.add_argument("--volumes", action="store_true", help="Also delete the current ThreatSight postgres volume")
    clean.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> None:
    os.chdir(ROOT)
    args = build_parser().parse_args(argv)
    if args.command == "allocate":
        print_ports(allocate_and_persist())
    elif args.command == "up":
        cmd_up(build=args.build, enterprise=args.enterprise, tunnel=args.tunnel)
    elif args.command == "down":
        cmd_down()
    elif args.command == "restart":
        cmd_restart()
    elif args.command == "ps":
        cmd_ps()
    elif args.command == "ports":
        cmd_ports()
    elif args.command == "inspect":
        cmd_inspect()
    elif args.command == "smoke":
        cmd_smoke()
    elif args.command == "test":
        cmd_test()
    elif args.command == "backup":
        cmd_backup()
    elif args.command == "deploy":
        cmd_deploy(allow_dirty=args.allow_dirty, skip_backup=args.skip_backup, skip_build=args.skip_build)
    elif args.command == "restore":
        cmd_restore(args.path, yes=args.yes)
    elif args.command == "clean":
        cmd_clean(volumes=args.volumes, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
