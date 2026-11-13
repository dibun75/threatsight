from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from threatsight_api.main import app

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}

pytestmark = pytest.mark.skipif(not LIVE, reason="requires live postgres")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_ops_exports_audit_and_grc_bundle(client: TestClient) -> None:
    status = client.get("/api/v1/ops/status")
    assert status.status_code == 200, status.text
    body = status.json()
    assert body["milestone"] == "M15"
    assert body["legal_compliance_claim"] is False
    assert body["autonomous_attack"] is False
    assert body["database_ok"] is True
    assert "COMPLIANT" not in status.text

    config = client.get("/api/v1/ops/config")
    assert config.status_code == 200
    assert config.json()["database_url"] == "[redacted]"
    assert config.json()["api_token"] == "[redacted]"

    findings = client.get("/api/v1/exports/findings.json")
    assert findings.status_code == 200, findings.text
    payload = findings.json()
    assert payload["format"] == "threatsight.export.v1"
    assert payload["legal_compliance_claim"] is False
    assert payload["kind"] == "findings"
    assert isinstance(payload["items"], list)

    csv_body = client.get("/api/v1/exports/findings.csv")
    assert csv_body.status_code == 200
    assert "id,title,status" in csv_body.text.splitlines()[0]

    bundle = client.get("/api/v1/exports/grc-bundle.json")
    assert bundle.status_code == 200, bundle.text
    grc = bundle.json()
    assert grc["format"] == "threatsight.grc.v1"
    assert grc["legal_compliance_claim"] is False
    assert grc["connector"] is False
    assert "systems" in grc
    assert "controls" in grc
    assert "evidence" in grc
    assert "findings" in grc
    assert "COMPLIANT" not in bundle.text

    audit = client.get("/api/v1/audit", params={"order": "desc", "limit": 10})
    assert audit.status_code == 200
    export_audit = client.get("/api/v1/exports/audit.json")
    assert export_audit.status_code == 200
    assert export_audit.json()["kind"] == "audit"

    unknown = client.get("/api/v1/exports/not-a-pack.json")
    assert unknown.status_code == 404
