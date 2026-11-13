"""Agent loop: model proposes tool calls, the gateway decides, the tool acts, the result goes back."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from threatsight_world.llm import ChatModel
from threatsight_world.policy import Decision, Gateway
from threatsight_world.tools import TOOLS, Context
from threatsight_world.world import World


@dataclass(frozen=True)
class ToolAttempt:
    name: str
    args: dict[str, Any]
    allowed: bool
    executed: bool
    rule: str | None
    held: bool = False


@dataclass
class Trace:
    events: list[dict[str, Any]] = field(default_factory=list)
    attempts: list[ToolAttempt] = field(default_factory=list)


def run_agent(
    model: ChatModel,
    system_prompt: str,
    user_message: str,
    tool_names: list[str],
    world: World,
    ctx: Context,
    gateway: Gateway,
    max_steps: int = 6,
) -> Trace:
    trace = Trace()
    specs = [TOOLS[n].spec() for n in tool_names]
    messages: list[dict[str, Any]] = [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_message}]
    trace.events.append({"type": "input", "text": user_message})
    for _ in range(max_steps):
        msg = model.complete(messages, specs)
        trace.events.append({"type": "assistant", **msg.to_dict()})
        if not msg.tool_calls:
            return trace
        messages.append(
            {
                "role": "assistant",
                "content": msg.content,
                "tool_calls": [{"id": c.id, "type": "function", "function": {"name": c.name, "arguments": json.dumps(c.arguments)}} for c in msg.tool_calls],
            }
        )
        for call in msg.tool_calls:
            decision, result, executed = _execute(call.name, call.arguments, tool_names, world, ctx, gateway)
            trace.attempts.append(ToolAttempt(call.name, call.arguments, decision.allow, executed, decision.rule, decision.hold))
            trace.events.append(
                {
                    "type": "tool",
                    "name": call.name,
                    "args": call.arguments,
                    "decision": {"allow": decision.allow, "rule": decision.rule, "reason": decision.reason, "hold": decision.hold},
                    "executed": executed,
                    "result": result,
                }
            )
            messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)})
    trace.events.append({"type": "note", "text": "max_steps reached"})
    return trace


def _execute(
    name: str, args: dict[str, Any], allowed_tools: list[str], world: World, ctx: Context, gateway: Gateway
) -> tuple[Decision, dict[str, Any], bool]:
    if name not in allowed_tools or name not in TOOLS:
        return Decision(False, "unknown-tool", "tool is not available to this agent"), {"error": "unknown tool"}, False
    if "_invalid" in args:
        return Decision(True, None, "arguments could not be parsed"), {"error": "invalid arguments"}, False
    decision = gateway.authorize(name, args, ctx, world)
    if not decision.allow and decision.hold:
        world.record("approval_requested", tool=name, args=dict(args), rule=decision.rule, reason=decision.reason)
        return decision, {"held_for_approval": True, "reason": decision.reason}, False
    if not decision.allow:
        return decision, {"denied": True, "reason": decision.reason}, False
    result = TOOLS[name].fn(world, ctx, args)
    world.record("tool_executed", tool=name)
    return decision, result, True
