from pathlib import Path

import pytest

from scripts.threatsight_docker import (
    PORT_LINE,
    UnsafeCleanupError,
    assert_cleanup_target,
    assert_no_unknown_project_containers,
    compose_command,
    is_threatsight_resource,
    next_free_port,
)


def test_port_line_parses_ipv4_and_ipv6() -> None:
    text = "0.0.0.0:8080->8000/tcp, [::]:8080->8000/tcp"
    matches = list(PORT_LINE.finditer(text))
    assert [m.group("host") for m in matches] == ["8080", "8080"]
    assert matches[0].group("container") == "8000"


def test_only_threatsight_names_are_owned() -> None:
    assert is_threatsight_resource("threatsight-api", "threatsight", "current")
    assert is_threatsight_resource("threatsight-postgres", "threatsight", "current")
    assert not is_threatsight_resource("threatsight-api", "", "current")
    assert not is_threatsight_resource("threatsight-api", "threatsight", "")
    assert not is_threatsight_resource("threatsight-api", "threatsight", "obsolete")
    assert not is_threatsight_resource("threatsight-api-copy", "threatsight", "current")
    assert not is_threatsight_resource("threatsight-2-api-1", "threatsight-2")
    assert not is_threatsight_resource("portainer", "")
    assert not is_threatsight_resource("infra-caddy", "infra")
    assert not is_threatsight_resource("other-research-1", "other-project")
    assert not is_threatsight_resource("portainer", "threatsight")


def test_cleanup_fails_closed_for_unknown_project_container() -> None:
    rows = [
        {
            "id": "abc",
            "name": "threatsight-api-copy",
            "project": "threatsight",
            "generation": "current",
            "ports": "",
            "status": "Up",
        }
    ]
    with pytest.raises(UnsafeCleanupError):
        assert_no_unknown_project_containers(rows)


def test_cleanup_refuses_foreign_resources() -> None:
    with pytest.raises(UnsafeCleanupError):
        assert_cleanup_target("container", "portainer")
    with pytest.raises(UnsafeCleanupError):
        assert_cleanup_target("container", "infra-watchdog")
    with pytest.raises(UnsafeCleanupError):
        assert_cleanup_target("image", "postgres:16-alpine")
    with pytest.raises(UnsafeCleanupError):
        assert_cleanup_target("volume", "portainer_data")
    with pytest.raises(UnsafeCleanupError):
        assert_cleanup_target("network", "infra_gateway")
    for foreign in (
        "infra-cloudflared",
        "infra-caddy",
        "other-app-api",
        "shop-api",
        "blog-app",
        "threatsight-scanner-cache",
    ):
        with pytest.raises(UnsafeCleanupError):
            assert_cleanup_target("container", foreign)
    with pytest.raises(UnsafeCleanupError):
        assert_cleanup_target("volume", "threatsight-trivy-cache")
    with pytest.raises(UnsafeCleanupError):
        assert_cleanup_target("container", "threatsight-api-copy")
    assert_cleanup_target("container", "threatsight-api")
    assert_cleanup_target("image", "threatsight-web:latest")
    assert_cleanup_target("image", "threatsight-demo-agent:latest")
    assert_cleanup_target("image", "threatsight-demo-site:latest")
    assert_cleanup_target("image", "threatsight-postgres:local")
    assert_cleanup_target("volume", "threatsight_postgres_data")
    assert_cleanup_target("network", "threatsight_default")


def test_enterprise_overlay_is_production_like() -> None:
    from pathlib import Path

    text = (Path(__file__).resolve().parents[1] / "docker-compose.enterprise.yml").read_text()
    assert "profiles:" in text
    assert "inprocess" in text
    assert "THREATSIGHT_API_TOKEN" in text
    assert "ports: !override []" in text
    assert "lab" in text


def test_lab_compose_has_labels_and_healthchecks() -> None:
    from pathlib import Path

    text = (Path(__file__).resolve().parents[1] / "docker-compose.yml").read_text()
    assert "com.threatsight.project: threatsight" in text
    assert "com.threatsight.generation: current" in text
    assert "com.threatsight.service: api" in text
    assert "com.threatsight.service: web" in text
    assert "com.threatsight.service: postgres" in text
    assert "threatsight-postgres:${THREATSIGHT_IMAGE_TAG:-23f8def}" in text
    assert "context: ./docker/postgres" in text
    postgres_dockerfile = (Path(__file__).resolve().parents[1] / "docker/postgres/Dockerfile").read_text()
    assert "apk add --no-cache su-exec" in postgres_dockerfile
    assert "rm -f /usr/local/bin/gosu" in postgres_dockerfile
    assert text.count("healthcheck:") >= 5
    assert "docker system prune" not in text


def test_lab_sidecars_are_internal_and_use_hardened_dependencies() -> None:
    root = Path(__file__).resolve().parents[1]
    compose = (root / "docker-compose.yml").read_text()
    assert 'expose:\n      - "8090"' in compose
    assert 'expose:\n      - "8091"' in compose

    for service in ("demo-agent", "demo-site"):
        project = (root / "apps" / service / "pyproject.toml").read_text()
        dockerfile = (root / "apps" / service / "Dockerfile").read_text()
        assert '"fastapi==0.162.0"' in project
        assert '"starlette==1.3.1"' in project
        assert "pip uninstall --yes pip setuptools wheel" in dockerfile


def test_compose_commands_do_not_remove_orphans() -> None:
    root = Path(__file__).resolve().parents[1]
    helper = (root / "scripts" / "threatsight_docker.py").read_text()
    tunnel = (root / "docker-compose.tunnel.yml").read_text()
    assert "--remove-orphans" not in helper
    assert str(root / "docker-compose.tunnel.yml") not in compose_command("ps")
    assert str(root / "docker-compose.tunnel.yml") in compose_command("ps", tunnel=True)
    assert 'caddy: "http://threatsight.io"' in tunnel
    assert 'caddy.reverse_proxy: "{{upstreams 3000}}"' in tunnel


def test_next_free_port_skips_foreign_occupancy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scripts.threatsight_docker.tcp_port_bindable",
        lambda port: port not in {8000, 8001},
    )
    chosen = next_free_port(
        8000,
        owners={8000: "portainer", 8001: "other"},
        our_names={"threatsight-api"},
    )
    assert chosen == 8002


def test_next_free_port_reuses_our_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("scripts.threatsight_docker.tcp_port_bindable", lambda _port: False)
    chosen = next_free_port(
        8000,
        owners={8000: "portainer", 8080: "threatsight-api"},
        our_names={"threatsight-api"},
    )
    assert chosen == 8080


def test_deploy_loads_every_live_overlay_and_pins_the_tag(tmp_path: Path) -> None:
    from scripts.threatsight_docker import LIVE_OVERLAYS, ROOT, deploy_compose_command, deploy_overlays

    env_file = tmp_path / "live.env"
    env_file.write_text("X=1\n")
    command = deploy_compose_command("ps", overlays=deploy_overlays({}), image_tag="abc1234", deploy_env=env_file)
    assert command[:3] == ["sudo", "env", "THREATSIGHT_IMAGE_TAG=abc1234"]
    for overlay in LIVE_OVERLAYS:
        assert str(ROOT / f"docker-compose.{overlay}.yml") in command
    assert str(ROOT / "docker-compose.tunnel.yml") in command
    assert command[command.index(str(env_file)) - 1] == "--env-file"
    assert command[-1] == "ps"


def test_deploy_overlays_can_be_narrowed_but_not_invented() -> None:
    from scripts.threatsight_docker import deploy_overlays

    assert deploy_overlays({"THREATSIGHT_DEPLOY_OVERLAYS": "tunnel, signing"}) == ("tunnel", "signing")
    with pytest.raises(SystemExit):
        deploy_overlays({"THREATSIGHT_DEPLOY_OVERLAYS": "tunnel nope"})


def test_read_env_file_handles_quotes_comments_and_export(tmp_path: Path) -> None:
    from scripts.threatsight_docker import read_env_file

    env_file = tmp_path / "e.env"
    env_file.write_text("# c\nexport A='x y'\nB=\"z\"\nC=plain\n\nnot a line\n")
    assert read_env_file(env_file) == {"A": "x y", "B": "z", "C": "plain"}


def test_deploy_never_rebuilds_the_pinned_signer_and_all_images_take_the_commit_tag() -> None:
    from scripts.threatsight_docker import DEPLOY_NO_BUILD_SERVICES

    root = Path(__file__).resolve().parents[1]
    assert "evidence-signer" in DEPLOY_NO_BUILD_SERVICES
    compose = (root / "docker-compose.yml").read_text()
    images = [line.split("image:", 1)[1].strip() for line in compose.splitlines() if line.strip().startswith("image:")]
    assert images and all("${THREATSIGHT_IMAGE_TAG:-" in image for image in images)
    assert ".deploy.env" in (root / ".gitignore").read_text().splitlines()


def test_services_without_healthcheck_count_as_ready_when_running() -> None:
    from scripts.threatsight_docker import all_services_ready

    assert all_services_ready("api\trunning\thealthy\nworker\trunning\t\n")
    assert not all_services_ready("api\trunning\tstarting\nworker\trunning\t\n")
    assert not all_services_ready("api\trunning\thealthy\nworker\trestarting\t\n")
    assert not all_services_ready("api\trunning\tunhealthy\n")
    assert not all_services_ready("")
