from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any
from uuid import UUID

from threatsight_api.domain.invariants import DETERMINISTIC_EVALUATOR


def canonical_envelope(
    *,
    run_id: UUID,
    control_id: UUID,
    control_identifier: str,
    ai_system_id: UUID,
    scenario_key: str,
    agent_version: str,
    configuration: dict[str, Any],
    tool_name: str | None,
    tool_arguments: dict[str, Any] | None,
    authorization_decision: str,
    policy_decision: str,
    tool_result: dict[str, Any] | None,
    completed_side_effect: str | None,
    evaluator: str,
    captured_at: datetime,
    narration_ignored: bool = True,
) -> dict[str, Any]:
    if evaluator != DETERMINISTIC_EVALUATOR:
        raise ValueError("Evidence envelope evaluator must be deterministic_policy")
    return {
        "run_id": str(run_id),
        "control_id": str(control_id),
        "control_identifier": control_identifier,
        "ai_system_id": str(ai_system_id),
        "scenario_key": scenario_key,
        "agent_version": agent_version,
        "configuration": configuration,
        "tool_name": tool_name,
        "tool_arguments": tool_arguments or {},
        "authorization_decision": authorization_decision,
        "policy_decision": policy_decision,
        "tool_result": tool_result,
        "completed_side_effect": completed_side_effect,
        "evaluator": evaluator,
        "captured_at": captured_at.isoformat(),
        "narration_ignored": narration_ignored,
        "synthetic": True,
    }


def hash_envelope(envelope: dict[str, Any]) -> str:
    payload = json.dumps(envelope, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
