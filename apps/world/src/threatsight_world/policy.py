"""Policy gateway placed in front of the tools.

A policy is plain JSON so it can be reviewed and diffed. No policy means an open gateway.
Unknown rule types raise at load time and any error while evaluating denies the call (fail closed).
A rule with ``"on_fail": "hold"`` does not refuse outright: the call is held for a named person to
approve or reject. A rule error still denies; it is never turned into a hold.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from threatsight_world.tools import Context
from threatsight_world.world import World

POLICY_DIR = Path(__file__).parent / "policies"
RULE_TYPES = {"requester_owns_case", "requester_owns_tenant", "supplier_registered", "max_amount_without_approver", "allow_actions", "internal_recipients_only"}


@dataclass(frozen=True)
class Decision:
    allow: bool
    rule: str | None = None
    reason: str = "no policy: open gateway"
    hold: bool = False


class PolicyError(ValueError):
    pass


class Gateway:
    def __init__(self, policy: dict[str, Any] | None = None) -> None:
        self.policy = policy
        self.name = policy["name"] if policy else "open"
        self.rules: list[dict[str, Any]] = []
        if policy:
            for rule in policy.get("rules", []):
                if rule.get("type") not in RULE_TYPES:
                    raise PolicyError(f"unknown rule type: {rule.get('type')!r}")
                if "id" not in rule or "tool" not in rule:
                    raise PolicyError("every rule needs an id and a tool")
                if rule.get("on_fail", "deny") not in {"deny", "hold"}:
                    raise PolicyError(f"on_fail must be deny or hold: {rule['id']}")
                self.rules.append(rule)

    @classmethod
    def from_name(cls, name: str) -> "Gateway":
        if name == "open":
            return cls(None)
        path = Path(name) if name.endswith(".json") else POLICY_DIR / f"{name}.json"
        return cls(json.loads(path.read_text()))

    def authorize(self, tool: str, args: dict[str, Any], ctx: Context, world: World) -> Decision:
        for rule in self.rules:
            if rule["tool"] != tool:
                continue
            try:
                ok, reason = self._check(rule, args, ctx, world)
            except Exception as exc:  # fail closed
                return Decision(False, rule["id"], f"rule error, denied: {exc}")
            if not ok:
                return Decision(False, rule["id"], reason, hold=rule.get("on_fail") == "hold")
        return Decision(True, None, "allowed" if self.rules else "no policy: open gateway")

    @staticmethod
    def _check(rule: dict[str, Any], args: dict[str, Any], ctx: Context, world: World) -> tuple[bool, str]:
        kind = rule["type"]
        if kind == "requester_owns_case":
            case = world.cases.get(str(args.get("case_id", "")))
            if case is None:
                return True, "case not found; nothing to protect"
            if case["owner"] != ctx.requester:
                return False, "requester does not own this case"
            return True, "owner"
        if kind == "requester_owns_tenant":
            tenant = world.tenants.get(str(args.get("tenant_id", "")))
            if tenant is None:
                return True, "tenant not found; nothing to protect"
            if tenant["owner"] != ctx.requester:
                return False, "requester is not a member of this tenant"
            return True, "member"
        if kind == "supplier_registered":
            if str(args.get("account", "")) not in world.suppliers:
                return False, "account not on file (not in the registered accounts)"
            return True, "registered"
        if kind == "max_amount_without_approver":
            amount = float(str(args.get(rule.get("amount_arg", "amount_nok"), "0")).replace(",", "").replace(" ", ""))
            if amount > float(rule["limit"]) and not ctx.approved_by:
                return False, "human approval required above limit"
            return True, "within limit or approved"
        if kind == "allow_actions":
            if str(args.get("action", "")) not in rule["actions"]:
                return False, "role is read-only: action not allowed"
            return True, "action allowed"
        if kind == "internal_recipients_only":
            to = str(args.get("to", "")).strip().lower()
            if not to.endswith("@" + world.domain):
                return False, "recipient is outside the organisation"
            return True, "internal recipient"
        raise PolicyError(kind)
