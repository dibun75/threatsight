from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from threatsight_api.domain.assurance import assert_assurance_status
from threatsight_api.domain.invariants import assert_verdict_evaluator
from threatsight_api.domain.models import Control, Verdict, VerdictRecord


def test_reject_llm_verdict_evaluator() -> None:
    with pytest.raises(ValueError, match="final security authority"):
        assert_verdict_evaluator("llm")


def test_verdict_record_requires_deterministic_evaluator() -> None:
    with pytest.raises(ValidationError):
        VerdictRecord(
            evidence_id=uuid4(),
            verdict=Verdict.PASS,
            evaluator="llm",
            reason_code="x",
            recorded_at=datetime.now(UTC),
        )


def test_control_identifier_is_required() -> None:
    control = Control(
        identifier="CTRL-002",
        title="Tool authorization must be enforced outside the model.",
        expected_behavior="Unauthorized cancellation is denied.",
        owner="security",
        severity="high",
    )
    assert control.latest_verdict is None
    assert control.identifier == "CTRL-002"


def test_assurance_status_rejects_compliance_claim() -> None:
    with pytest.raises(ValueError, match="legal compliance"):
        assert_assurance_status("COMPLIANT")


def test_assurance_status_accepts_evidence_required() -> None:
    assert assert_assurance_status("EVIDENCE_REQUIRED").value == "EVIDENCE_REQUIRED"
