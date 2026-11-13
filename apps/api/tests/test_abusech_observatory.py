import json

import pytest

from threatsight_api.observatory.abusech import FEEDS, fetch_feed, parse_feodo, parse_urlhaus
from threatsight_api.observatory.contract import ObservatoryError


class Response:
    def __init__(self, url: str, body: bytes):
        self.url, self.body = url, body

    def geturl(self):
        return self.url

    def read(self, amount):
        return self.body[:amount]


class Opener:
    def __init__(self, url: str, body: bytes = b"[]"):
        self.url, self.body, self.request = url, body, None

    def open(self, request, timeout):
        assert timeout == 30
        self.request = request
        return Response(self.url, self.body)


def test_feodo_rows_keep_source_country_and_drop_private_hosts():
    payload = json.dumps([
        {"ip_address": "23.94.68.19", "port": 443, "status": "online", "country": "us", "malware": "Emotet", "first_seen": "2026-11-01 10:00:00", "last_online": "2026-11-06", "as_name": "EXAMPLE-AS"},
        {"ip_address": "10.0.0.5", "port": 443, "malware": "Emotet"},
        {"ip_address": "23.94.68.19", "port": 8080, "malware": "Dup"},
        {"ip_address": "not-an-ip", "malware": "x"},
        {"ip_address": "45.9.9.9", "port": 99999, "country": "ZZZ", "malware": "QakBot"},
    ]).encode()
    rows = parse_feodo(payload)
    assert [row["indicator"] for row in rows] == ["23.94.68.19", "45.9.9.9"]
    assert rows[0]["country_code"] == "US" and rows[0]["last_seen"] == "2026-11-06"
    assert rows[1]["country_code"] is None and rows[1]["port"] is None
    assert rows[0]["kind"] == "botnet_c2"


def test_urlhaus_rows_never_carry_a_country_and_strip_queries_and_credentials():
    payload = json.dumps({"1": [
        {"url": "http://Bad.example/x/payload.exe?token=secret", "url_status": "online", "threat": "malware_download", "dateadded": "2026-11-06 01:02:03 UTC"},
        {"url": "http://user:pw@bad.example/a", "threat": "malware_download"},
        {"url": "http://192.168.1.4/a", "threat": "malware_download"},
        {"url": "http://93.184.216.35:8080/a", "threat": "malware_download", "url_status": "offline"},
    ]}).encode()
    rows = parse_urlhaus(payload)
    assert [row["indicator"] for row in rows] == ["http://bad.example/x/payload.exe", "http://93.184.216.35:8080/a"]
    assert rows[1]["port"] == 8080
    assert all(row["country_code"] is None for row in rows)
    assert all("?" not in row["indicator"] and "@" not in row["indicator"] for row in rows)


def test_urlhaus_api_shape_is_parsed():
    payload = json.dumps({"query_status": "ok", "urls": [
        {"url": "http://bad.example/x.exe", "url_status": "online", "threat": "malware_download", "date_added": "2026-11-07 16:00:12 UTC"},
    ]}).encode()
    rows = parse_urlhaus(payload)
    assert [row["indicator"] for row in rows] == ["http://bad.example/x.exe"]
    assert rows[0]["first_seen"] == "2026-11-07"
    with pytest.raises(ObservatoryError):
        parse_urlhaus(json.dumps({"query_status": "unknown_auth_key"}).encode())


def test_schema_drift_is_rejected():
    for parser in (parse_feodo, parse_urlhaus):
        with pytest.raises(ObservatoryError) as error:
            parser(b"not json")
        assert error.value.code == "schema_drift"
    with pytest.raises(ObservatoryError):
        parse_feodo(b'{"a": 1}')


def test_fetch_is_get_only_pinned_and_sends_key_only_when_configured(tmp_path):
    host, path = FEEDS["feodo"]
    opener = Opener(f"https://{host}{path}")
    fetch_feed("feodo", opener=opener)
    assert opener.request.method == "GET" and "Auth-key" not in opener.request.headers
    key = tmp_path / "key"
    key.write_text("fixture-auth-key-value\n")
    key.chmod(0o600)
    keyed = Opener(f"https://{host}{path}")
    fetch_feed("feodo", str(key), opener=keyed)
    assert keyed.request.headers["Auth-key"] == "fixture-auth-key-value"


def test_fetch_rejects_unknown_feed_and_redirect_to_other_host():
    with pytest.raises(ObservatoryError):
        fetch_feed("other")
    with pytest.raises(ObservatoryError) as error:
        fetch_feed("urlhaus", opener=Opener("https://evil.example/v1/urls/recent/limit/1000/"))
    assert error.value.code == "redirect_rejected"
