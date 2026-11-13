"""Workspace-scoped, on-demand GreyNoise enrichment requests."""

from __future__ import annotations

from datetime import UTC, datetime
import uuid

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import text

from threatsight_api.api.deps import DbSession, WorkspaceScope
from threatsight_api.observatory.contract import ObservatoryError
from threatsight_api.observatory.greynoise import public_ipv4

router = APIRouter(prefix="/telemetry/observations/greynoise", tags=["telemetry"])
_COLUMNS = "id,ip_address,status,requested_at,completed_at,expires_at,noise,riot,classification,name,provider,reference_url,last_seen,message"


class LookupIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str
    refresh: bool = False


def _address(value: str) -> str:
    try:
        return public_ipv4(value)
    except ObservatoryError as exc:
        raise HTTPException(
            status_code=422, detail="A public IPv4 address is required"
        ) from exc


def _out(row) -> dict:
    return {
        "id": str(row["id"]),
        "ip": row["ip_address"],
        "status": row["status"],
        "requested_at": row["requested_at"].isoformat(),
        "completed_at": row["completed_at"].isoformat()
        if row["completed_at"]
        else None,
        "expires_at": row["expires_at"].isoformat() if row["expires_at"] else None,
        "noise": row["noise"],
        "riot": row["riot"],
        "classification": row["classification"],
        "name": row["name"],
        "provider": row["provider"],
        "reference_url": row["reference_url"],
        "last_seen": row["last_seen"].isoformat() if row["last_seen"] else None,
        "message": row["message"],
        "source": "GreyNoise Community",
        "does_not_mean": "This source-reported IP context is not attacker attribution or proof of targeting, reachability, exploitation, compromise, or customer impact.",
    }


@router.get("")
def get_lookup(
    db: DbSession, scope: WorkspaceScope, ip: str = Query(min_length=7, max_length=15)
) -> dict:
    row = (
        db.execute(
            text(
                f"SELECT {_COLUMNS} FROM greynoise_lookups WHERE workspace_id=:workspace AND ip_address=:ip ORDER BY requested_at DESC LIMIT 1"
            ),
            {"workspace": scope.id, "ip": _address(ip)},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="GreyNoise lookup not found")
    return _out(row)


@router.post("", status_code=202)
def request_lookup(body: LookupIn, db: DbSession, scope: WorkspaceScope) -> dict:
    if scope.role not in {"operator", "workspace-admin", "platform-admin"}:
        raise HTTPException(status_code=403, detail="Workspace role is not permitted")
    if body.refresh and scope.role not in {"workspace-admin", "platform-admin"}:
        raise HTTPException(
            status_code=403, detail="Administrator role is required for refresh"
        )
    address = _address(body.ip)
    existing = (
        db.execute(
            text(
                f"SELECT {_COLUMNS} FROM greynoise_lookups WHERE workspace_id=:workspace AND ip_address=:ip "
                "AND (status IN ('pending','running') OR (status IN ('succeeded','not_found') AND expires_at > now())) "
                "ORDER BY requested_at DESC LIMIT 1"
            ),
            {"workspace": scope.id, "ip": address},
        )
        .mappings()
        .first()
    )
    if existing is not None and not body.refresh:
        return _out(existing)
    day = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    count = db.execute(
        text(
            "SELECT count(*) FROM greynoise_lookups WHERE workspace_id=:workspace AND requested_at>=:day"
        ),
        {"workspace": scope.id, "day": day},
    ).scalar_one()
    if count >= 10:
        raise HTTPException(
            status_code=429, detail="Daily GreyNoise lookup limit reached"
        )
    lookup_id = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO greynoise_lookups (id,workspace_id,ip_address,status,requested_by,refresh_requested) "
            "VALUES (:id,:workspace,:ip,'pending',:subject,:refresh)"
        ),
        {
            "id": lookup_id,
            "workspace": scope.id,
            "ip": address,
            "subject": scope.subject[:200],
            "refresh": body.refresh,
        },
    )
    db.commit()
    row = (
        db.execute(
            text(f"SELECT {_COLUMNS} FROM greynoise_lookups WHERE id=:id"),
            {"id": lookup_id},
        )
        .mappings()
        .one()
    )
    return _out(row)
