from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException
from sqlalchemy import func, select

from threatsight_api.api.deps import Actor, DbSession, Limit, Offset, require_entity
from threatsight_api.api.schemas import (
    DiscoveredAssetDetail,
    DiscoveredAssetOut,
    DiscoveryScanOut,
    DiscoverySignalOut,
    DiscoverySourceCreate,
    DiscoverySourceOut,
    ScanCreate,
    SignalMapIn,
    SignalReviewIn,
)
from threatsight_api.config import get_settings
from threatsight_api.discovery.engine import (
    DiscoveryEngineError,
    bootstrap_demo,
    map_signal_to_control,
    register_source,
    review_signal,
    scan_source,
)
from threatsight_api.discovery.safety import DiscoverySafetyError
from threatsight_api.domain.enums import CandidateReviewStatus
from threatsight_api.persistence.models import (
    DiscoveredAsset,
    DiscoveryScan,
    DiscoverySignal,
    DiscoverySource,
)

router = APIRouter(prefix="/discovery", tags=["discovery"])


def _http(exc: DiscoveryEngineError | DiscoverySafetyError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


def _asset_out(db, asset: DiscoveredAsset) -> DiscoveredAssetOut:
    pending = db.scalar(
        select(func.count())
        .select_from(DiscoverySignal)
        .where(
            DiscoverySignal.asset_id == asset.id,
            DiscoverySignal.review_status == CandidateReviewStatus.PENDING.value,
        )
    ) or 0
    return DiscoveredAssetOut(
        id=asset.id,
        source_id=asset.source_id,
        scan_id=asset.scan_id,
        kind=asset.kind,
        title=asset.title,
        url=asset.url,
        summary=asset.summary,
        status=asset.status,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
        pending_signals=int(pending),
    )


@router.post("/demo/bootstrap")
def bootstrap(db: DbSession, actor: Actor) -> dict:
    settings = get_settings()
    try:
        return bootstrap_demo(db, settings, actor)
    except (DiscoveryEngineError, DiscoverySafetyError) as exc:
        _http(exc)


@router.get("/status")
def discovery_status(db: DbSession) -> dict:
    settings = get_settings()
    sources = db.scalar(select(func.count()).select_from(DiscoverySource)) or 0
    assets = db.scalar(select(func.count()).select_from(DiscoveredAsset)) or 0
    pending = db.scalar(
        select(func.count())
        .select_from(DiscoverySignal)
        .where(DiscoverySignal.review_status == CandidateReviewStatus.PENDING.value)
    ) or 0
    return {
        "discovery_engine": "authorized_demo_site_fetch",
        "adapter": settings.discovery_adapter,
        "demo_site_url": settings.demo_site_url,
        "kill_switch": settings.kill_switch,
        "sandbox_default": settings.sandbox_default,
        "llm_may_authorize_fetch": False,
        "unrestricted_crawl": False,
        "legal_compliance_claim": False,
        "synthetic_demo_labelled": True,
        "sources": int(sources),
        "assets": int(assets),
        "pending_signals": int(pending),
    }


@router.post("/sources", status_code=201, response_model=DiscoverySourceOut)
def create_source(body: DiscoverySourceCreate, db: DbSession, actor: Actor) -> DiscoverySourceOut:
    settings = get_settings()
    try:
        source = register_source(
            db,
            url=body.url,
            title=body.title,
            owner=body.owner or actor,
            settings=settings,
            refresh_authorization=body.refresh_authorization,
        )
    except (DiscoveryEngineError, DiscoverySafetyError) as exc:
        _http(exc)
    return DiscoverySourceOut.model_validate(source)


@router.get("/sources", response_model=list[DiscoverySourceOut])
def list_sources(db: DbSession, limit: Limit = 50, offset: Offset = 0) -> list[DiscoverySourceOut]:
    rows = list(
        db.scalars(select(DiscoverySource).order_by(DiscoverySource.created_at.desc()).offset(offset).limit(limit))
    )
    return [DiscoverySourceOut.model_validate(item) for item in rows]


@router.get("/sources/{source_id}", response_model=DiscoverySourceOut)
def get_source(source_id: uuid.UUID, db: DbSession) -> DiscoverySourceOut:
    source = require_entity(db, DiscoverySource, source_id, "Discovery source")
    return DiscoverySourceOut.model_validate(source)


@router.post("/sources/{source_id}/scans", status_code=201, response_model=DiscoveryScanOut)
def create_scan(source_id: uuid.UUID, body: ScanCreate, db: DbSession, actor: Actor) -> DiscoveryScanOut:
    source = require_entity(db, DiscoverySource, source_id, "Discovery source")
    settings = get_settings()
    try:
        scan = scan_source(
            db,
            source,
            confirm_execution=body.confirm_execution,
            actor=actor,
            settings=settings,
        )
    except (DiscoveryEngineError, DiscoverySafetyError) as exc:
        _http(exc)
    return DiscoveryScanOut.model_validate(scan)


@router.get("/scans", response_model=list[DiscoveryScanOut])
def list_scans(db: DbSession, source_id: uuid.UUID | None = None, limit: Limit = 50, offset: Offset = 0) -> list[DiscoveryScanOut]:
    stmt = select(DiscoveryScan).order_by(DiscoveryScan.started_at.desc())
    if source_id is not None:
        stmt = stmt.where(DiscoveryScan.source_id == source_id)
    rows = list(db.scalars(stmt.offset(offset).limit(limit)))
    return [DiscoveryScanOut.model_validate(item) for item in rows]


@router.get("/assets", response_model=list[DiscoveredAssetOut])
def list_assets(db: DbSession, source_id: uuid.UUID | None = None, limit: Limit = 50, offset: Offset = 0) -> list[DiscoveredAssetOut]:
    stmt = select(DiscoveredAsset).order_by(DiscoveredAsset.created_at.desc())
    if source_id is not None:
        stmt = stmt.where(DiscoveredAsset.source_id == source_id)
    rows = list(db.scalars(stmt.offset(offset).limit(limit)))
    return [_asset_out(db, item) for item in rows]


@router.get("/assets/{asset_id}", response_model=DiscoveredAssetDetail)
def get_asset(asset_id: uuid.UUID, db: DbSession) -> DiscoveredAssetDetail:
    asset = require_entity(db, DiscoveredAsset, asset_id, "Discovered asset")
    signals = list(
        db.scalars(select(DiscoverySignal).where(DiscoverySignal.asset_id == asset.id).order_by(DiscoverySignal.created_at))
    )
    base = _asset_out(db, asset)
    return DiscoveredAssetDetail(
        **base.model_dump(),
        signals=[DiscoverySignalOut.model_validate(item) for item in signals],
    )


@router.get("/signals", response_model=list[DiscoverySignalOut])
def list_signals(
    db: DbSession,
    review_status: str | None = None,
    asset_id: uuid.UUID | None = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> list[DiscoverySignalOut]:
    stmt = select(DiscoverySignal).order_by(DiscoverySignal.created_at.desc())
    if review_status:
        stmt = stmt.where(DiscoverySignal.review_status == review_status)
    if asset_id is not None:
        stmt = stmt.where(DiscoverySignal.asset_id == asset_id)
    rows = list(db.scalars(stmt.offset(offset).limit(limit)))
    return [DiscoverySignalOut.model_validate(item) for item in rows]


@router.get("/signals/{signal_id}", response_model=DiscoverySignalOut)
def get_signal(signal_id: uuid.UUID, db: DbSession) -> DiscoverySignalOut:
    signal = require_entity(db, DiscoverySignal, signal_id, "Discovery signal")
    return DiscoverySignalOut.model_validate(signal)


@router.post("/signals/{signal_id}/review", response_model=DiscoverySignalOut)
def review(signal_id: uuid.UUID, body: SignalReviewIn, db: DbSession, actor: Actor) -> DiscoverySignalOut:
    signal = require_entity(db, DiscoverySignal, signal_id, "Discovery signal")
    try:
        updated = review_signal(
            db,
            signal,
            decision=body.decision.value,
            comment=body.comment,
            actor=actor,
        )
    except DiscoveryEngineError as exc:
        _http(exc)
    return DiscoverySignalOut.model_validate(updated)


@router.post("/signals/{signal_id}/map-control", response_model=DiscoverySignalOut)
def map_control(signal_id: uuid.UUID, body: SignalMapIn, db: DbSession, actor: Actor) -> DiscoverySignalOut:
    signal = require_entity(db, DiscoverySignal, signal_id, "Discovery signal")
    try:
        map_signal_to_control(db, signal, body.control_id, actor)
    except DiscoveryEngineError as exc:
        _http(exc)
    db.refresh(signal)
    return DiscoverySignalOut.model_validate(signal)
