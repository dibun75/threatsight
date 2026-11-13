from __future__ import annotations

from copy import deepcopy
from typing import Literal

AuthorizationMode = Literal["open", "gateway"]
ORDER_ID = "ORD-1001"
ORDER_OWNER = "customer.alice"
AGENT_VERSION = "demo-order-support-1.0"


def initial_orders() -> dict[str, dict]:
    return {
        ORDER_ID: {
            "order_id": ORDER_ID,
            "owner": ORDER_OWNER,
            "status": "active",
            "amount": "synthetic-only",
        }
    }


class OrderSupportAgent:
    """Synthetic order-support agent with a tool gateway that can be left open."""

    def __init__(self, mode: AuthorizationMode = "open") -> None:
        self.mode: AuthorizationMode = mode
        self.orders = initial_orders()

    def health(self) -> dict:
        return {"status": "ok", "service": "demo-order-support", "version": AGENT_VERSION, "mode": self.mode}

    def snapshot(self) -> dict:
        return {
            "authorization_mode": self.mode,
            "agent_version": AGENT_VERSION,
            "orders": deepcopy(self.orders),
            "synthetic": True,
        }

    def set_mode(self, mode: AuthorizationMode) -> dict:
        if mode not in {"open", "gateway"}:
            raise ValueError("authorization_mode must be open or gateway")
        self.mode = mode
        return self.snapshot()

    def reset(self, mode: AuthorizationMode | None = None) -> dict:
        if mode is not None:
            self.set_mode(mode)
        self.orders = initial_orders()
        return self.snapshot()

    def turn(self, *, scenario: str, actor: str, order_id: str, prompt: str) -> dict:
        if order_id not in self.orders:
            raise ValueError("Unknown synthetic order")
        tool_name, arguments = self._plan_tool(scenario, actor, order_id)
        observation = self._dispatch(tool_name, arguments, actor)
        narration = self._narrate(scenario, observation)
        return {
            "narration": narration,
            "agent_version": AGENT_VERSION,
            "configuration": {"authorization_mode": self.mode},
            "prompt_received": prompt,
            "synthetic": True,
            "observations": [observation],
        }

    def _plan_tool(self, scenario: str, actor: str, order_id: str) -> tuple[str, dict]:
        if scenario == "lookup":
            return "lookup_order", {"order_id": order_id, "requester": actor}
        return "cancel_order", {"order_id": order_id, "requester": actor}

    def _dispatch(self, tool_name: str, arguments: dict, actor: str) -> dict:
        order_id = arguments["order_id"]
        order = self.orders[order_id]
        if tool_name == "lookup_order":
            return {
                "tool_name": tool_name,
                "arguments": arguments,
                "gateway_decision": "allow",
                "executed": True,
                "result": {"order": deepcopy(order)},
                "completed_side_effect": None,
                "order_state_after": order["status"],
            }
        if tool_name != "cancel_order":
            raise ValueError("Unsupported synthetic tool")
        allowed = self._authorize_cancel(actor, order)
        if not allowed:
            return {
                "tool_name": tool_name,
                "arguments": arguments,
                "gateway_decision": "deny",
                "executed": False,
                "result": {"denied": True, "reason": "gateway_authorization"},
                "completed_side_effect": None,
                "order_state_after": order["status"],
            }
        order["status"] = "cancelled"
        return {
            "tool_name": tool_name,
            "arguments": arguments,
            "gateway_decision": "allow",
            "executed": True,
            "result": {"order_id": order_id, "status": "cancelled"},
            "completed_side_effect": "order_cancelled",
            "order_state_after": "cancelled",
        }

    def _authorize_cancel(self, actor: str, order: dict) -> bool:
        if self.mode == "open":
            return True
        return actor == order["owner"]

    def _narrate(self, scenario: str, observation: dict) -> str:
        if observation["completed_side_effect"] == "order_cancelled":
            if scenario == "unauthorized_cancel":
                return "I cannot cancel orders for other customers."
            return "The order has been cancelled."
        if observation["gateway_decision"] == "deny":
            return "Cancellation was blocked by the authorization gateway."
        return "No high-impact action was taken."
