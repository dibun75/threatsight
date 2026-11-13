import json
from pathlib import Path

import pytest

from threatsight_api.observatory.contract import ObservatoryError
from threatsight_api.observatory.threatfox import (
    ENDPOINT,
    fetch_recent,
    parse_recent,
    read_auth_key,
)


class Response:
    def __init__(self, body: bytes):
        self.body = body

    def geturl(self):
        return ENDPOINT

    def read(self, amount):
        return self.body[:amount]


class Opener:
    def __init__(self, body: bytes):
        self.body = body

    def open(self, request, timeout):
        assert timeout == 30
        assert request.full_url == ENDPOINT
        assert request.method == "POST"
        assert json.loads(request.data) == {"query": "get_iocs", "days": 1}
        assert request.headers["Auth-key"] == "fixture-auth-key-value"
        return Response(self.body)


def fixture() -> bytes:
    return json.dumps(
        {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "23.94.68.19:443",
                    "ioc_type": "ip:port",
                    "threat_type": "botnet_cc",
                    "malware_printable": "Dridex",
                    "confidence_level": 75,
                    "first_seen": "2026-11-05 10:00:00 UTC",
                    "last_seen": "2026-11-05 11:00:00 UTC",
                    "reporter": "drop-me",
                    "comment": "drop-me",
                    "tags": ["drop-me"],
                },
                {
                    "ioc": "evil.example",
                    "ioc_type": "domain",
                    "threat_type": "payload_delivery",
                    "malware": "win.test",
                    "confidence_level": 50,
                    "first_seen": "2026-11-05 10:00:00 UTC",
                    "last_seen": None,
                },
                {
                    "ioc": "127.0.0.1:22",
                    "ioc_type": "ip:port",
                    "threat_type": "botnet_cc",
                    "malware": "bad",
                    "confidence_level": 100,
                },
            ],
        }
    ).encode()


def test_parser_keeps_bounded_infrastructure_and_drops_reporter_fields():
    rows = parse_recent(fixture())
    assert [row["indicator_type"] for row in rows] == ["ip:port", "domain"]
    assert rows[0]["port"] == 443
    encoded = json.dumps(rows)
    assert (
        "reporter" not in encoded and "comment" not in encoded and "tags" not in encoded
    )
    assert rows[0]["metadata_safe"]["malware_family"] == "Dridex"


def test_schema_and_indicator_validation_fail_closed():
    with pytest.raises(ObservatoryError):
        parse_recent(b'{"query_status":"ok"}')
    assert (
        parse_recent(
            json.dumps(
                {
                    "query_status": "ok",
                    "data": [
                        {
                            "ioc": "http://user:pass@evil.example/",
                            "ioc_type": "url",
                            "threat_type": "botnet_cc",
                            "malware": "x",
                            "confidence_level": 50,
                        }
                    ],
                }
            ).encode()
        )
        == []
    )


def test_client_reads_key_from_file_and_uses_only_official_endpoint(tmp_path: Path):
    key = tmp_path / "key"
    key.write_text("fixture-auth-key-value\n")
    key.chmod(0o640)
    assert read_auth_key(str(key)) == "fixture-auth-key-value"
    assert fetch_recent(str(key), opener=Opener(fixture()))
    with pytest.raises(ObservatoryError):
        fetch_recent(str(key), days=8, opener=Opener(fixture()))


def test_worker_and_compose_keep_usage_and_secret_gates() -> None:
    root = Path(__file__).resolve().parents[3]
    worker = (
        root / "apps/api/src/threatsight_api/observatory/threatfox_worker.py"
    ).read_text()
    base = (root / "docker-compose.yml").read_text()
    overlay = (root / "docker-compose.threatfox.yml").read_text()
    assert "THREATSIGHT_THREATFOX_USAGE_MODE" in worker
    assert "personal_evaluation" in worker and "commercial_entitled" in worker
    assert 'THREATSIGHT_THREATFOX_ENABLED: "false"' in base
    assert "intel-worker:" in overlay
    assert "/run/secrets/threatfox_auth_key" in overlay
    assert "api:" not in overlay and "web:" not in overlay
