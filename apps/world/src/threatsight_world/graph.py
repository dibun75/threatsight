"""Capability graph and blast-radius score, derived from the agents' real tool lists and a policy.

Nothing here is hand-typed per agent: the tools come from the scenarios, the guardrails come from the
policy file. Only three small tables are declared: where each tool leads, how sensitive each store is,
and which untrusted inputs each agent reads. The score formula is deliberately plain so it can be
explained to a non-expert and challenged. Impact carries half the weight because the worst thing an
agent can do matters more than how many things it can do.

    reach       = min(100, 25 * tools + 15 * data stores + 20 * untrusted inputs)
    impact      = highest tool impact the agent can call
    sensitivity = most sensitive data store it can reach
    raw         = 0.50 * impact + 0.25 * sensitivity + 0.25 * reach
    guardrails  = share of the agent's non-read tools that have at least one policy rule
    score       = round(raw * (1 - 0.7 * guardrails))
"""
from __future__ import annotations

import argparse
import json
from typing import Any

from threatsight_world.policy import Gateway
from threatsight_world.scenarios import scenarios_for
from threatsight_world.tools import TOOLS

IMPACT = {"read": 30, "write": 60, "external": 70, "high": 95}
TOOL_DATA = {
    "lookup_case": "Case records",
    "read_invoice": "Finance ledger",
    "approve_payment": "Finance ledger",
    "send_email": "Mail gateway",
    "cloud_admin": "Cloud account",
    "read_document": "Document store",
    "lookup_tenant": "Customer tenants",
    "issue_refund": "Billing ledger",
    "iam_admin": "Identity provider",
}
DATA_SENSITIVITY = {"Case records": 90, "Finance ledger": 80, "Mail gateway": 70, "Cloud account": 85, "Document store": 40,
                    "Customer tenants": 90, "Billing ledger": 80, "Identity provider": 95}
AGENT_INPUTS = {
    "payment-injection": ["Inbound email", "Supplier invoices"],
    "cross-citizen-record": ["Citizen chat"],
    "cloud-ticket-acl": ["Support tickets"],
    "document-injection": ["Uploaded documents"],
    "helio-refund-redirect": ["Customer email", "Invoices"],
    "helio-cross-tenant": ["Customer chat"],
    "helio-iam-escalation": ["Incident tickets"],
    "helio-runbook-injection": ["Runbooks"],
}


def build_graph(gateway: Gateway, profile: str = "nordvik") -> dict[str, Any]:
    ruled_tools = {r["tool"] for r in gateway.rules}
    agents = []
    for sc in scenarios_for(profile):
        tools = [TOOLS[t] for t in sc.tools]
        data = sorted({TOOL_DATA[t.name] for t in tools})
        inputs = AGENT_INPUTS[sc.id]
        top = max(tools, key=lambda t: IMPACT[t.impact])
        impact = IMPACT[top.impact]
        sensitivity = max(DATA_SENSITIVITY[d] for d in data)
        reach = min(100, 25 * len(tools) + 15 * len(data) + 20 * len(inputs))
        risky = [t for t in tools if t.impact != "read"]
        # Weighted by impact: guarding the payment tool counts for more than guarding email.
        weight = sum(IMPACT[t.impact] for t in risky)
        guard = (sum(IMPACT[t.impact] for t in risky if t.name in ruled_tools) / weight) if risky else 1.0
        raw = 0.50 * impact + 0.25 * sensitivity + 0.25 * reach
        score = round(raw * (1 - 0.7 * guard))
        agents.append(
            {
                "id": sc.id,
                "agent": sc.agent,
                "control": sc.control.id,
                "inputs": inputs,
                "tools": [{"name": t.name, "impact": t.impact, "data": TOOL_DATA[t.name], "guarded": t.name in ruled_tools} for t in tools],
                "data": data,
                "factors": {"reach": reach, "impact": impact, "sensitivity": sensitivity, "guardrails": round(guard * 100)},
                "score": score,
                "worst_path": {"input": inputs[0], "tool": top.name, "data": TOOL_DATA[top.name]},
            }
        )
    return {"policy": gateway.name, "profile": profile, "agents": agents}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m threatsight_world.graph", description="Print the capability graph and blast-radius scores as JSON.")
    p.add_argument("--policy", default="open", help="open, nordvik-hardened, helio-hardened or a path to a policy .json")
    p.add_argument("--profile", default="nordvik", choices=["nordvik", "helio"])
    p.add_argument("--compare", action="store_true", help="show open and the profile's hardened scores side by side")
    args = p.parse_args(argv)
    if args.compare:
        a, b = build_graph(Gateway(None), args.profile), build_graph(Gateway.from_name(f"{args.profile}-hardened"), args.profile)
        for x, y in zip(a["agents"], b["agents"]):
            print(f"{x['agent']:<22} {x['score']:>3} -> {y['score']:>3}   worst path: {x['worst_path']['input']} -> {x['worst_path']['tool']} -> {x['worst_path']['data']}")
        return 0
    print(json.dumps(build_graph(Gateway.from_name(args.policy), args.profile), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
