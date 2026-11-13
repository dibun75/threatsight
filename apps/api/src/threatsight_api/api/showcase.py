from __future__ import annotations

from fastapi import APIRouter, HTTPException

from threatsight_api.api.deps import Actor, DbSession
from threatsight_api.api.schemas import ShowcaseBootstrapIn, ShowcaseResetIn
from threatsight_api.assurance.engine import AssuranceEngineError
from threatsight_api.assurance.safety import AssuranceSafetyError
from threatsight_api.config import get_settings
from threatsight_api.showcase.engine import bootstrap_showcase, reset_showcase, showcase_status

router = APIRouter(prefix="/showcase", tags=["showcase"])


def _engine_http(exc: AssuranceEngineError | AssuranceSafetyError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get("/status")
def get_status() -> dict:
    return showcase_status(get_settings())


@router.post("/demo/bootstrap")
def bootstrap(body: ShowcaseBootstrapIn, db: DbSession, actor: Actor) -> dict:
    try:
        return bootstrap_showcase(
            db,
            get_settings(),
            actor,
            confirm_execution=body.confirm_execution,
        )
    except (AssuranceEngineError, AssuranceSafetyError) as exc:
        _engine_http(exc)
    raise AssertionError("unreachable")


@router.post("/demo/reset")
def reset(body: ShowcaseResetIn, db: DbSession, actor: Actor) -> dict:
    try:
        return reset_showcase(
            db,
            get_settings(),
            actor,
            reseed=body.reseed,
            confirm_execution=body.confirm_execution,
        )
    except (AssuranceEngineError, AssuranceSafetyError) as exc:
        _engine_http(exc)
    raise AssertionError("unreachable")
