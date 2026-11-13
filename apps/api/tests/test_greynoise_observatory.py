import json
from pathlib import Path

import pytest

from threatsight_api.observatory.contract import ObservatoryError
from threatsight_api.observatory.greynoise import fetch, parse, public_ipv4


class Response:
    def __init__(self, body: bytes, url: str):
        self.body, self.url = body, url

    def geturl(self):
        return self.url

    def read(self, amount):
        return self.body[:amount]


class Opener:
    def __init__(self, body: bytes):
        self.body = body

    def open(self, request, timeout):
        assert request.full_url == "https://api.greynoise.io/v3/community/8.8.8.8"
        assert request.method == "GET"
        assert timeout == 15
        assert "key" not in request.headers
        return Response(self.body, request.full_url)


def fixture() -> bytes:
    return json.dumps(
        {
            "ip": "8.8.8.8",
            "noise": False,
            "riot": True,
            "classification": "benign",
            "name": "Google Public DNS",
            "link": "https://viz.greynoise.io/ip/8.8.8.8",
            "last_seen": "2026-11-05",
            "message": "Success",
        }
    ).encode()


def test_client_is_single_ip_and_parser_keeps_safe_source_fields():
    result = parse(fetch("8.8.8.8", opener=Opener(fixture())), "8.8.8.8")
    assert result["classification"] == "benign"
    assert result["riot"] is True
    assert result["reference_url"].startswith("https://viz.greynoise.io/")


@pytest.mark.parametrize(
    "value", ["127.0.0.1", "169.254.169.254", "10.0.0.1", "::1", "bad"]
)
def test_non_public_ipv4_fails_before_network(value):
    with pytest.raises(ObservatoryError):
        public_ipv4(value)


def test_architecture_prohibits_bulk_and_background_collection():
    root = Path(__file__).resolve().parents[3]
    adr = (root / "docs/reference/decisions/0042-greynoise-on-demand-only.md").read_text()
    worker = (
        root / "apps/api/src/threatsight_api/observatory/greynoise_worker.py"
    ).read_text()
    ui = (root / "apps/web/components/command/ThreatObservatory.tsx").read_text()
    assert "No scheduler, background sweep, bulk lookup" in adr
    assert "LIMIT 1" in worker
    assert "Investigate one public IP" in ui
    assert "api.greynoise.io" not in ui
