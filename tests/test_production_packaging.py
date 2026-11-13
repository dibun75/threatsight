from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_production_api_image_excludes_development_payload() -> None:
    dockerfile = (ROOT / "apps/api/Dockerfile.production").read_text()
    assert "COPY tests" not in dockerfile
    assert ".[dev]" not in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "pip wheel --wheel-dir /wheels ." in dockerfile


def test_production_web_image_runs_as_non_root() -> None:
    dockerfile = (ROOT / "apps/web/Dockerfile.production").read_text()
    assert "USER 1001:1001" in dockerfile
    assert 'CMD ["node", "server.js"]' in dockerfile


def test_enterprise_compose_gates_api_on_one_shot_migration() -> None:
    compose = (ROOT / "docker-compose.enterprise.yml").read_text()
    assert "dockerfile: Dockerfile.production" in compose
    assert 'THREATSIGHT_RUN_MIGRATIONS: "false"' in compose
    assert "condition: service_completed_successfully" in compose
    assert 'command: ["python", "-m", "threatsight_api.migrate"]' in compose
