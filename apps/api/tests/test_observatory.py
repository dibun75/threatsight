import json
from pathlib import Path

import pytest

from threatsight_api.observatory.client import fetch_dataset
from threatsight_api.observatory.contract import ObservatoryError, parse_threat_intel, parse_top_ips, parse_top_ports


class _Headers:
    def get_content_type(self):
        return "text/plain"


class _Response:
    status = 200
    headers = _Headers()

    def __init__(self, body: bytes, url: str) -> None:
        self.body = body
        self.url = url

    def geturl(self) -> str:
        return self.url

    def read(self, amount: int) -> bytes:
        return self.body[:amount]


class _Opener:
    def __init__(self, response: _Response) -> None:
        self.response = response

    def open(self, request, timeout):  # noqa: ANN001
        assert timeout == 30
        assert request.full_url.startswith("https://feeds.dshield.org/")
        assert "Authorization" not in request.headers
        return self.response


def test_dshield_top_ips_keeps_only_public_ipv4_and_bounds() -> None:
    rows = parse_top_ips(b"# comment\n23.94.68.19\tscanner.example\n127.0.0.1\tlocal\n10.0.0.1\tprivate\n")
    assert rows == [{
        "kind": "scanning_source",
        "indicator_type": "ipv4",
        "indicator": "23.94.68.19",
        "category": "high_volume_source",
        "detail": "scanner.example",
        "rank": 1,
        "reference_url": "https://feeds.dshield.org/feeds/topips.txt",
    }]


def test_dshield_ports_are_validated_and_not_linked_to_ips() -> None:
    rows = parse_top_ports(b"443\thttps\tHTTP over TLS\n0\tbad\tinvalid\n65536\tbad\tinvalid\n22\tssh\tSecure Shell\n")
    assert [row["port"] for row in rows] == [443, 22]
    assert all(row["indicator_type"] == "port" for row in rows)
    assert all("ip" not in row for row in rows)


def test_static_threat_intel_classifies_without_claiming_attack_or_customer_target() -> None:
    payload = (
        "2026-11-01\t2026-11-05\t23.94.68.19\tdshield\tUS\n"
        "2026-11-01\t2026-11-05\t8.8.8.8\tdshieldssh\tUS\n"
        "2026-11-01\t2026-11-05\t1.1.1.1\tminer\tAU\n"
        "2026-11-01\t2026-11-05\t127.0.0.1\tscanner\tNO\n"
        "2026-11-01\t2026-11-05\t9.9.9.9\tunclassified\tUS\n"
    ).encode()
    rows = parse_threat_intel(payload)
    assert [row["category"] for row in rows] == ["multi_port_scanning", "ssh_scanning", "cryptomining_infrastructure"]
    assert all("attacker" not in json.dumps(row).lower() for row in rows)
    assert all("customer" not in json.dumps(row).lower() for row in rows)


def test_malformed_rows_are_ignored_and_binary_input_fails_closed() -> None:
    assert parse_threat_intel(b"not-a-tabular-row") == []
    assert parse_top_ips(b"23.94.68.19\t<script>\n") == []
    with pytest.raises(ObservatoryError) as binary:
        parse_threat_intel(b"bad\x00row")
    assert binary.value.code == "encoding"


def test_client_uses_only_allowlisted_endpoint() -> None:
    url = "https://feeds.dshield.org/feeds/topips.txt"
    assert fetch_dataset("top_ips", opener=_Opener(_Response(b"23.94.68.19\thost\n", url)))
    with pytest.raises(ObservatoryError) as rejected:
        fetch_dataset("https://evil.example/feed")
    assert rejected.value.code == "request_rejected"


def test_client_accepts_current_feed_size_but_stays_bounded() -> None:
    from threatsight_api.observatory.client import MAX_RESPONSE

    url = "https://feeds.dshield.org/feeds/topips.txt"
    current = b"x" * 11_100_000  # threatintel.txt size seen in Nov 2026
    assert len(fetch_dataset("top_ips", opener=_Opener(_Response(current, url)))) == len(current)
    with pytest.raises(ObservatoryError) as too_large:
        fetch_dataset("top_ips", opener=_Opener(_Response(b"x" * (MAX_RESPONSE + 1), url)))
    assert too_large.value.code == "response_too_large"


def test_api_and_web_do_not_collect_or_embed_a_feed() -> None:
    root = Path(__file__).resolve().parents[1]
    api = (root / "src/threatsight_api/api/telemetry.py").read_text()
    assert "fetch_dataset" not in api
    web = root.parent / "web/components/command/ThreatObservatory.tsx"
    source = web.read_text()
    assert "feeds.dshield.org" not in source
    assert "/api/v1/telemetry/observations" in source


def test_placeholder_country_codes_are_not_reported_as_countries() -> None:
    payload = (
        "2026-11-01\t2026-11-05\t23.94.68.19\tdshield\tXX\n"
        "2026-11-01\t2026-11-05\t8.8.8.8\tdshieldssh\tus\n"
    ).encode()
    rows = parse_threat_intel(payload)
    assert [row["country_code"] for row in rows] == [None, "US"]
