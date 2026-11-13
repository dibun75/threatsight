import json
import os
from email.message import EmailMessage
from pathlib import Path
from urllib.error import HTTPError

import pytest

from threatsight_api.telemetry.client import HOST, fetch_dataset, load_token
from threatsight_api.telemetry.contract import RadarError, parse_document
from threatsight_api.telemetry.publish import _country_slice, collect_window
from threatsight_api.telemetry.worker import maybe_collect

META = {
    "dateRange": [{"startTime": "2026-11-01T00:00:00Z", "endTime": "2026-11-02T00:00:00Z"}],
    "lastUpdated": "2026-11-02T00:05:00Z",
    "normalization": "PERCENTAGE",
    "units": [{"name": "requests", "value": "percentage"}],
    "confidenceInfo": {"level": 4, "annotations": [{"description": "Coverage varies.", "eventType": "GENERAL"}]},
}


def envelope(result: dict) -> bytes:
    return json.dumps({"success": True, "result": result}).encode()


def origin(rows: list[dict] | None = None) -> bytes:
    return envelope({"meta": META, "top_0": rows if rows is not None else [{"originCountryAlpha2": "US", "originCountryName": "United States", "rank": 1, "value": "12.5"}]})


class _Headers(EmailMessage):
    def get_content_type(self) -> str:
        return self["Content-Type"]


class _Response:
    def __init__(self, body: bytes, *, url: str, content_type: str = "application/json", status: int = 200) -> None:
        self.status = status
        self._body = body
        self._url = url
        self.headers = _Headers()
        self.headers["Content-Type"] = content_type

    def geturl(self) -> str:
        return self._url

    def read(self, amount: int) -> bytes:
        return self._body[:amount]


class _Opener:
    def __init__(self, response=None, error=None) -> None:
        self.response = response
        self.error = error
        self.calls = 0

    def open(self, request, timeout):  # noqa: ANN001
        self.calls += 1
        assert request.get_header("Authorization", "").startswith("Bearer ")
        assert timeout == 20
        if self.error:
            raise self.error
        return self.response


class _DB:
    def __init__(self, lock: bool = True) -> None:
        self.lock = lock
        self.statements: list[str] = []

    def execute(self, statement, params=None):  # noqa: ANN001
        sql = str(statement)
        self.statements.append(sql)
        value = self.lock if "pg_try_advisory_lock" in sql else None
        return type("Result", (), {"scalar": lambda self_: value})()


def test_anonymous_telemetry_response_is_not_stored(monkeypatch) -> None:
    monkeypatch.setenv("THREATSIGHT_AUTH_MODE", "local")
    monkeypatch.setenv("THREATSIGHT_PUBLIC_DEMO", "false")
    from threatsight_api.config import get_settings
    from fastapi.testclient import TestClient
    from threatsight_api.main import app

    get_settings.cache_clear()
    try:
        response = TestClient(app).get("/api/v1/telemetry/activity")
        assert response.status_code == 401
        assert response.headers["cache-control"] == "no-store"
        assert "cloudflare_radar_token" not in response.text
    finally:
        get_settings.cache_clear()


def test_official_origin_target_pairs_series_and_mitigation() -> None:
    parsed = parse_document(origin(), kind="origin")
    assert parsed["rows"][0]["country"] == "US"
    target = envelope({"meta": META, "top_0": [{"targetCountryAlpha2": "NO", "targetCountryName": "Norway", "rank": 4, "value": "0"}]})
    assert parse_document(target, kind="target")["rows"][0]["value"] == 0
    pairs = envelope({"meta": META, "top_0": [{"originCountryAlpha2": "US", "originCountryName": "United States", "targetCountryAlpha2": "NO", "targetCountryName": "Norway", "value": "1"}]})
    assert parse_document(pairs, kind="pairs")["rows"][0]["target"] == "NO"
    series = envelope({"meta": META, "serie_0": {"timestamps": ["2026-11-01T00:00:00Z"], "values": ["3"]}})
    assert parse_document(series, kind="timeseries")["rows"][0]["value"] == 3
    mitigation = envelope({"meta": META, "summary_0": {"waf": "40"}})
    assert parse_document(mitigation, kind="mitigation")["rows"] == [{"product": "waf", "value": 40}]


def test_malformed_json_is_rejected() -> None:
    with pytest.raises(RadarError) as caught:
        parse_document(b"<html>", kind="origin")
    assert caught.value.code == "malformed_json"


def test_null_confidence_is_stored_as_not_supplied_and_other_shapes_fail() -> None:
    absent = dict(META)
    absent["confidenceInfo"] = None
    parsed = parse_document(envelope({"meta": absent, "serie_0": {"timestamps": ["2026-11-01T00:00:00Z"], "values": ["1"]}}), kind="timeseries")
    assert parsed["meta"]["confidence"] == {"level": None, "supplied": False}
    null_level = dict(META)
    null_level["confidenceInfo"] = {"level": None, "annotations": []}
    parsed = parse_document(envelope({"meta": null_level, "top_0": []}), kind="origin")
    assert parsed["meta"]["confidence"]["supplied"] is False
    numeric = parse_document(origin(), kind="origin")
    assert numeric["meta"]["confidence"] == {"level": 4, "supplied": True}
    with pytest.raises(RadarError) as caught:
        bad = dict(META)
        bad["confidenceInfo"] = {"level": "high", "annotations": []}
        parse_document(envelope({"meta": bad, "top_0": []}), kind="origin")
    assert caught.value.code == "schema"


def test_norway_absence_is_not_zero_and_bad_fields_fail() -> None:
    assert parse_document(origin([]), kind="origin")["rows"] == []
    with pytest.raises(RadarError) as caught:
        parse_document(envelope({"meta": META, "top_0": [{"clientCountryAlpha2": "NO", "value": "1"}]}), kind="origin")
    assert caught.value.code == "schema"
    with pytest.raises(RadarError) as country:
        parse_document(origin([{"originCountryAlpha2": "no", "originCountryName": "Norway", "rank": 1, "value": "1"}]), kind="origin")
    assert country.value.code == "country_code"
    with pytest.raises(RadarError):
        parse_document(origin([{"originCountryAlpha2": "NO", "originCountryName": "<script>", "rank": 1, "value": "1"}]), kind="origin")


def test_http_failures_do_not_follow_another_host(monkeypatch) -> None:
    url = f"https://{HOST}/client/v4/radar/attacks/layer7/top/locations/origin?dateRange=1d&format=json"
    sleeps: list[float] = []
    opener = _Opener(error=HTTPError(url, 429, "slow", _Headers(), None))
    opener.error.headers["Retry-After"] = "2"
    with pytest.raises(RadarError):
        fetch_dataset("origin", "24h", token="secret-token", opener=opener, sleeper=sleeps.append)
    assert sleeps
    assert "secret-token" not in repr(sleeps)
    redirected = _Opener(_Response(origin(), url="https://evil.example/steal"))
    with pytest.raises(RadarError) as redirect:
        fetch_dataset("origin", "24h", token="secret-token", opener=redirected, sleeper=lambda _delay: None)
    assert redirect.value.code == "redirect_rejected"
    html = _Opener(_Response(b"<html></html>", url=url, content_type="text/html"))
    with pytest.raises(RadarError) as content:
        fetch_dataset("origin", "24h", token="secret-token", opener=html, sleeper=lambda _delay: None)
    assert content.value.code == "content_type"
    huge = _Opener(_Response(b"{" + b"x" * 1_000_001, url=url))
    with pytest.raises(RadarError) as size:
        fetch_dataset("origin", "24h", token="secret-token", opener=huge, sleeper=lambda _delay: None)
    assert size.value.code == "response_too_large"
    with pytest.raises(RadarError):
        fetch_dataset("origin", "24h", token="secret-token", opener=_Opener(error=TimeoutError()), sleeper=lambda _delay: None)
    denied = HTTPError(url, 401, "no", _Headers(), None)
    with pytest.raises(RadarError) as auth:
        fetch_dataset("origin", "24h", token="secret-token", opener=_Opener(error=denied), sleeper=lambda _delay: None)
    assert auth.value.code == "unauthorized"
    failed = HTTPError(url, 500, "no", _Headers(), None)
    with pytest.raises(RadarError):
        fetch_dataset("origin", "24h", token="secret-token", opener=_Opener(error=failed), sleeper=lambda _delay: None)


def test_rankings_and_paths_are_bounded_and_timeseries_keeps_location() -> None:
    seen: dict[str, str] = {}

    class Recording:
        def open(self, request, timeout):  # noqa: ANN001
            seen["url"] = request.full_url
            return _Response(origin(), url=request.full_url)

    fetch_dataset("origin", "24h", token="secret-token", opener=Recording(), sleeper=lambda _delay: None)
    assert "limit=100" in seen["url"]
    assert "location=" not in seen["url"]
    fetch_dataset("pairs", "24h", token="secret-token", opener=Recording(), sleeper=lambda _delay: None)
    assert "limit=25" in seen["url"]
    fetch_dataset("timeseries", "24h", token="secret-token", location="NO", opener=Recording(), sleeper=lambda _delay: None)
    assert "location=NO" in seen["url"]
    assert "limit=" not in seen["url"]


def test_norway_slice_keeps_only_norway() -> None:
    document = {"meta": {"normalization": "PERCENTAGE"}, "rows": [
        {"country": "US", "name": "United States", "rank": 1, "value": 20.0},
        {"country": "NO", "name": "Norway", "rank": 81, "value": 0.068},
    ]}
    assert _country_slice(document, "NO")["rows"] == [document["rows"][1]]
    assert _country_slice({"meta": document["meta"], "rows": [document["rows"][0]]}, "NO")["rows"] == []


def test_partial_collection_does_not_parse_a_later_success() -> None:
    calls = {"count": 0}

    def fetch(dataset, window, location=None):  # noqa: ANN001
        calls["count"] += 1
        if calls["count"] == 2:
            raise RadarError("http_status")
        return 200, envelope({"meta": META, "serie_0": {"timestamps": ["2026-11-01T00:00:00Z"], "values": ["3"]}})

    with pytest.raises(RadarError):
        collect_window("24h", fetch)
    assert calls["count"] == 2


def test_token_file_rules(tmp_path: Path) -> None:
    token = tmp_path / "cloudflare_radar_token"
    token.write_text("radar-token")
    os.chmod(token, 0o644)
    with pytest.raises(RadarError) as permissions:
        load_token(str(token), allowed_path=str(token))
    assert permissions.value.code == "token_permissions"
    os.chmod(token, 0o600)
    assert load_token(str(token), allowed_path=str(token)) == "radar-token"
    os.chmod(token, 0o640)
    assert load_token(str(token), allowed_path=str(token)) == "radar-token"
    token.write_bytes(b"radar-token\n")
    os.chmod(token, 0o640)
    assert load_token(str(token), allowed_path=str(token)) == "radar-token"
    with pytest.raises(RadarError):
        load_token("/tmp/other-token", allowed_path=str(token))
    with pytest.raises(RadarError):
        load_token("/run/secrets/cloudflare_radar_token")


def test_worker_disabled_kill_switch_and_duplicate(monkeypatch) -> None:
    monkeypatch.delenv("THREATSIGHT_RADAR_ENABLED", raising=False)
    assert maybe_collect(_DB(), enabled=False)["state"] == "disabled"
    monkeypatch.setenv("THREATSIGHT_INTEL_KILL_SWITCH", "true")
    assert maybe_collect(_DB(), enabled=True)["state"] == "disabled"
    monkeypatch.setenv("THREATSIGHT_INTEL_KILL_SWITCH", "false")
    assert maybe_collect(_DB(lock=False), enabled=True)["state"] == "collecting"


def test_cancellation_and_api_do_not_read_the_token(monkeypatch) -> None:
    monkeypatch.setenv("THREATSIGHT_RADAR_TOKEN_FILE", "/run/secrets/cloudflare_radar_token")
    monkeypatch.setattr("threatsight_api.telemetry.worker.load_token", lambda path: "not-logged")
    called = {"fetch": 0}

    def fetch(*_args, **_kwargs):
        called["fetch"] += 1
        raise AssertionError("cancelled collection fetched")

    assert maybe_collect(_DB(), enabled=True, fetch=fetch, running=False)["state"] == "cancelled"
    assert called["fetch"] == 0
    root = Path(__file__).resolve().parents[1]
    api = (root / "src/threatsight_api/api/telemetry.py").read_text()
    reader = (root / "src/threatsight_api/telemetry/read.py").read_text()
    assert "load_token" not in api
    assert "Authorization" not in reader
    assert "THREATSIGHT_RADAR_TOKEN_FILE" not in api


@pytest.mark.skipif(os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() not in {"1", "true", "yes"}, reason="postgres")
def test_publication_keeps_the_last_good_snapshot() -> None:
    from fastapi.testclient import TestClient
    from sqlalchemy import text

    from threatsight_api.main import app
    from threatsight_api.persistence.session import SessionLocal
    from threatsight_api.telemetry.publish import publish, record_failure
    from threatsight_api.telemetry.read import activity as read_activity

    document = parse_document(origin(), kind="origin")
    pair_document = parse_document(envelope({"meta": META, "top_0": [{
        "originCountryAlpha2": "US", "originCountryName": "United States",
        "targetCountryAlpha2": "NO", "targetCountryName": "Norway", "value": "1.25",
    }]}), kind="pairs")
    with TestClient(app):
        with SessionLocal() as db:
            publish(db, {"origin": document, "pairs": pair_document}, window="24h")
            db.commit()
            record_failure(db, window="24h", code="http_status", has_current=True)
            db.commit()
            current = db.execute(text("SELECT count(*) FROM telemetry_snapshots WHERE dataset = 'origin' AND is_current")).scalar()
            assert current == 1
            failed = db.execute(text("SELECT status FROM telemetry_runs ORDER BY started_at DESC LIMIT 1")).scalar()
            assert failed == "failed_using_last_known_good"

            response = read_activity(db)
            assert response["paths"][0]["country"] == "US"
            assert response["paths"][0]["target"] == "NO"


def test_compose_keeps_the_token_on_the_worker_override() -> None:
    root = Path(__file__).resolve().parents[3]
    base = (root / "docker-compose.yml").read_text()
    overlay = (root / "docker-compose.telemetry.yml").read_text()
    assert "THREATSIGHT_RADAR_TOKEN_FILE" not in base
    assert "cloudflare_radar_token" not in base
    assert "THREATSIGHT_RADAR_ENABLED: \"false\"" in base
    assert "intel-worker" in overlay
    assert "/run/secrets/cloudflare_radar_token" in overlay
