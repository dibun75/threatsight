from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from threatsight_api.config import Settings
from threatsight_api.connectors.execution import (
    backoff_seconds,
    contains_secret_material,
    hashes_match,
    issue_runner_token,
    payload_too_large,
    redact,
    token_hash,
)
from threatsight_api.runner import control_plane_base
from threatsight_api.connectors.sdk import (
    CollectionEnvelope,
    ConnectorMaturity,
    ConnectorMode,
    NormalizedRecord,
    PageRequest,
)


def _record() -> NormalizedRecord:
    return NormalizedRecord(
        kind="asset",
        external_id="fixture-1",
        collected_at=datetime.now(UTC),
        truth_state="fixture_tested",
        attributes={"name": "bounded"},
        provenance={"source": "sanitized_fixture"},
    )


def test_sdk_is_bounded_read_only_and_envelopes_are_idempotent() -> None:
    assert PageRequest(limit=500).limit == 500
    with pytest.raises(ValidationError):
        PageRequest(limit=501)
    record = _record()
    digest = CollectionEnvelope.hash_records([record])
    envelope = CollectionEnvelope(
        connector_key="fixture",
        job_id="job-1",
        idempotency_key="stable-key",
        sequence=0,
        mode=ConnectorMode.FIXTURE,
        maturity=ConnectorMaturity.FIXTURE_TESTED,
        records=[record],
        emitted_at=datetime.now(UTC),
        content_hash=digest,
    )
    assert envelope.sdk_version == "v1"
    assert digest == CollectionEnvelope.hash_records([record])


def test_secret_redaction_is_recursive_and_runner_token_is_hash_only() -> None:
    payload = {
        "token": "do-not-return",
        "nested": [{"password": "also-secret", "safe": "visible"}],
        "authorization": "Bearer secret",
    }
    assert redact(payload) == {
        "token": "[REDACTED]",
        "nested": [{"password": "[REDACTED]", "safe": "visible"}],
        "authorization": "[REDACTED]",
    }
    token, digest = issue_runner_token()
    assert token.startswith("tsr_")
    assert token not in digest
    assert token_hash(token) == digest
    assert contains_secret_material({"nested": [{"api_key": "value"}]})
    assert not contains_secret_material({"scope": "bounded"})


def test_retry_backoff_is_bounded_and_runtime_limits_fail_closed() -> None:
    assert [backoff_seconds(i) for i in (1, 2, 3)] == [2, 4, 8]
    assert backoff_seconds(100) == 900
    with pytest.raises(ValueError, match="CONCURRENCY"):
        Settings(connector_workspace_concurrency=0).validate_runtime_security()


def test_runner_auth_and_payloads_fail_closed() -> None:
    assert hashes_match("a" * 64, "a" * 64)
    assert not hashes_match("a" * 64, "b" * 64)
    assert not hashes_match("short", "a" * 64)
    assert payload_too_large({"scope": "x" * 70_000})
    assert not payload_too_large({"scope": "bounded"})
    assert control_plane_base("http://threatsight-api:8000/") == "http://threatsight-api:8000"
    with pytest.raises(ValueError):
        control_plane_base("http://user:secret@threatsight-api:8000")
    with pytest.raises(ValueError):
        control_plane_base("file:///tmp/control")


def test_maturity_does_not_promote_fixture_to_live() -> None:
    assert ConnectorMaturity.FIXTURE_TESTED != ConnectorMaturity.LIVE_VERIFIED
    with pytest.raises(ValidationError):
        NormalizedRecord(
            kind="asset",
            external_id="x",
            collected_at=datetime.now(UTC),
            truth_state="safe",
            provenance={"source": "fixture"},
        )
