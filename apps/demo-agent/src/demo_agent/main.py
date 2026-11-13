from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from demo_agent.runtime import AGENT_VERSION, ORDER_ID, OrderSupportAgent

agent = OrderSupportAgent(mode="open")
app = FastAPI(title="ThreatSight demo order-support agent", version=AGENT_VERSION)


class TurnIn(BaseModel):
    scenario: str = Field(min_length=1, max_length=64)
    actor: str = Field(min_length=1, max_length=200)
    order_id: str = Field(default=ORDER_ID, min_length=1, max_length=64)
    prompt: str = Field(min_length=1, max_length=4000)


class ModeIn(BaseModel):
    authorization_mode: str = Field(min_length=1, max_length=32)


class ResetIn(BaseModel):
    authorization_mode: str | None = Field(default=None, max_length=32)


@app.get("/health")
def health() -> dict:
    return agent.health()


@app.get("/v1/state")
def state() -> dict:
    return agent.snapshot()


@app.post("/v1/reset")
def reset(body: ResetIn | None = None) -> dict:
    mode = body.authorization_mode if body else None
    try:
        return agent.reset(mode)  # type: ignore[arg-type]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/config")
def configure(body: ModeIn) -> dict:
    try:
        return agent.set_mode(body.authorization_mode)  # type: ignore[arg-type]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/turn")
def turn(body: TurnIn) -> dict:
    try:
        return agent.turn(scenario=body.scenario, actor=body.actor, order_id=body.order_id, prompt=body.prompt)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
