from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from threatsight_api.config import Settings
from threatsight_api.discovery.extract import extract_page
from threatsight_api.discovery.fetch import DiscoveryFetchError, fetch_page, join_same_origin
from threatsight_api.discovery.robots import RobotsRules, parse_robots
from threatsight_api.discovery.safety import (
    DiscoverySafetyError,
    assert_scan_allowed,
    assert_url_allowed,
    normalize_url,
    origin_of,
)
from threatsight_api.domain.enums import (
    AuditAction,
    CandidateReviewStatus,
    EvidenceStatus,
    EvidenceType,
)
from threatsight_api.persistence.models import (
    ControlRecord,
    DiscoveredAsset,
    DiscoveryScan,
    DiscoverySignal,
    DiscoverySource,
    EvidenceControlLink,
    EvidenceRecord,
)
from threatsight_api.services.audit import record_audit

AUTHORIZATION_HOURS = 24
DEFAULT_TITLE = "Northwind Copilot (synthetic demo site)"


class DiscoveryEngineError(RuntimeError):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


def utc_now() -> datetime:
    return datetime.now(UTC)


def bootstrap_demo(db: Session, settings: Settings, actor: str) -> dict:
    url = normalize_url(settings.demo_site_url)
    source = register_source(
        db,
        url=url,
        title=DEFAULT_TITLE,
        owner=actor,
        settings=settings,
        refresh_authorization=True,
    )
    return {
        "source_id": str(source.id),
        "url": source.url,
        "authorized": source.authorized,
        "authorization_expires_at": source.authorization_expires_at.isoformat()
        if source.authorization_expires_at
        else None,
        "synthetic": True,
        "adapter": settings.discovery_adapter,
    }


def register_source(
    db: Session,
    *,
    url: str,
    title: str | None,
    owner: str,
    settings: Settings,
    refresh_authorization: bool = False,
) -> DiscoverySource:
    assert_url_allowed(url, settings)
    normalized = normalize_url(url)
    existing = db.scalar(select(DiscoverySource).where(DiscoverySource.url == normalized))
    expires = utc_now() + timedelta(hours=AUTHORIZATION_HOURS)
    if existing is not None:
        if not refresh_authorization:
            raise DiscoveryEngineError("This URL is already registered", 409)
        existing.authorized = True
        existing.authorization_expires_at = expires
        existing.owner = owner
        if title:
            existing.title = title[:200]
        existing.status = "registered"
        db.flush()
        record_audit(
            db,
            entity_type="discovery_source",
            entity_id=existing.id,
            action=AuditAction.UPDATE,
            actor=owner,
            payload={"url": existing.url, "authorized": True},
        )
        return existing
    source = DiscoverySource(
        url=normalized,
        title=(title or _title_from_url(normalized))[:200],
        owner=owner,
        authorized=True,
        authorization_expires_at=expires,
        status="registered",
    )
    db.add(source)
    try:
        db.flush()
    except IntegrityError as exc:
        raise DiscoveryEngineError("This URL is already registered", 409) from exc
    record_audit(
        db,
        entity_type="discovery_source",
        entity_id=source.id,
        action=AuditAction.CREATE,
        actor=owner,
        payload={"url": source.url, "authorized": True},
    )
    return source


def scan_source(
    db: Session,
    source: DiscoverySource,
    *,
    confirm_execution: bool,
    actor: str,
    settings: Settings,
) -> DiscoveryScan:
    try:
        assert_scan_allowed(settings, confirm_execution=confirm_execution)
        assert_url_allowed(source.url, settings)
    except DiscoverySafetyError as exc:
        raise DiscoveryEngineError(str(exc), exc.status_code) from exc
    if not source.authorized:
        raise DiscoveryEngineError("Source is not authorized for fetch", 403)
    if source.authorization_expires_at and source.authorization_expires_at < utc_now():
        raise DiscoveryEngineError("Source authorization has expired", 403)

    scan = DiscoveryScan(
        source_id=source.id,
        status="running",
        confirm_execution=confirm_execution,
        robots_checked=False,
        pages_fetched=0,
        actor=actor,
        started_at=utc_now(),
    )
    db.add(scan)
    db.flush()
    record_audit(
        db,
        entity_type="discovery_scan",
        entity_id=scan.id,
        action=AuditAction.SCAN,
        actor=actor,
        payload={"source_id": str(source.id), "url": source.url},
    )

    try:
        _run_scan(db, source, scan, settings)
    except (DiscoverySafetyError, DiscoveryFetchError, DiscoveryEngineError) as exc:
        scan.status = "failed"
        if isinstance(exc, DiscoverySafetyError):
            scan.status = "blocked"
        scan.error = str(exc)[:2000]
        scan.finished_at = utc_now()
        source.status = "failed"
        source.last_scan_id = scan.id
        db.flush()
    return scan


def _run_scan(db: Session, source: DiscoverySource, scan: DiscoveryScan, settings: Settings) -> None:
    origin = origin_of(source.url)
    try:
        robots_page = fetch_page(f"{origin}/robots.txt", settings)
        rules = parse_robots(robots_page.text)
    except DiscoveryFetchError:
        rules = RobotsRules(allows=("/",), disallows=())
    scan.robots_checked = True
    start_path = urlparse(source.url).path or "/"
    if not rules.allowed(start_path):
        raise DiscoverySafetyError("robots.txt disallows this path", 403)

    to_visit = [source.url]
    seen: set[str] = set()
    fetched: list[tuple] = []
    hasher = hashlib.sha256()

    while to_visit and len(fetched) < settings.discovery_max_pages:
        current = to_visit.pop(0)
        if current in seen:
            continue
        seen.add(current)
        path = urlparse(current).path or "/"
        if not rules.allowed(path):
            continue
        page = fetch_page(current, settings)
        if page.status != 200:
            continue
        hasher.update(page.body)
        extracted = extract_page(path, page.text)
        fetched.append((page.final_url, extracted, page))
        for href in extracted.links:
            joined = join_same_origin(page.final_url, href)
            if joined and joined not in seen:
                to_visit.append(joined)

    content_hash = hasher.hexdigest()
    scan.pages_fetched = len(fetched)
    scan.content_hash = content_hash

    previous = db.scalar(
        select(DiscoveryScan)
        .where(
            DiscoveryScan.source_id == source.id,
            DiscoveryScan.status.in_(("completed", "unchanged")),
            DiscoveryScan.id != scan.id,
        )
        .order_by(DiscoveryScan.started_at.desc())
    )
    if previous is not None and previous.content_hash == content_hash:
        scan.status = "unchanged"
        scan.finished_at = utc_now()
        source.status = "ready"
        source.last_scan_id = scan.id
        db.flush()
        return

    for final_url, extracted, page in fetched:
        asset = db.scalar(
            select(DiscoveredAsset).where(
                DiscoveredAsset.source_id == source.id,
                DiscoveredAsset.url == final_url,
            )
        )
        if asset is None:
            asset = DiscoveredAsset(
                source_id=source.id,
                scan_id=scan.id,
                kind=extracted.kind,
                title=extracted.title[:200],
                url=final_url,
                summary=extracted.summary,
                status="discovered",
            )
            db.add(asset)
            db.flush()
        else:
            asset.scan_id = scan.id
            asset.kind = extracted.kind
            asset.title = extracted.title[:200]
            asset.summary = extracted.summary
            asset.status = "discovered"
            db.flush()
        page_hash = hashlib.sha256(page.body).hexdigest()
        created_keys: set[tuple[str, str, str]] = set()
        for signal in extracted.signals:
            identity = (signal.signal_kind, final_url, page_hash)
            if identity in created_keys:
                continue
            duplicate = db.scalar(
                select(DiscoverySignal).where(
                    DiscoverySignal.source_id == source.id,
                    DiscoverySignal.signal_kind == signal.signal_kind,
                    DiscoverySignal.page_url == final_url,
                    DiscoverySignal.content_hash == page_hash,
                )
            )
            if duplicate is not None:
                created_keys.add(identity)
                continue
            created_keys.add(identity)
            row = DiscoverySignal(
                source_id=source.id,
                scan_id=scan.id,
                asset_id=asset.id,
                signal_kind=signal.signal_kind,
                title=signal.title[:200],
                statement=signal.statement,
                quote=signal.quote,
                page_url=final_url,
                content_hash=page_hash,
                review_status=CandidateReviewStatus.PENDING.value,
            )
            db.add(row)
    db.flush()
    scan.status = "completed"
    scan.finished_at = utc_now()
    source.status = "ready"
    source.last_scan_id = scan.id
    db.flush()


def review_signal(
    db: Session,
    signal: DiscoverySignal,
    *,
    decision: str,
    comment: str | None,
    actor: str,
) -> DiscoverySignal:
    if signal.review_status == CandidateReviewStatus.APPROVED.value:
        raise DiscoveryEngineError("Signal is already approved", 409)
    if signal.review_status == CandidateReviewStatus.REJECTED.value:
        raise DiscoveryEngineError("Signal is already rejected", 409)
    if decision == CandidateReviewStatus.PENDING.value:
        raise DiscoveryEngineError("Review decision cannot be pending", 400)
    signal.review_status = decision
    signal.reviewer = actor
    signal.review_comment = comment
    signal.reviewed_at = utc_now()
    if decision == CandidateReviewStatus.APPROVED.value:
        _materialize_evidence(db, signal, actor)
    record_audit(
        db,
        entity_type="discovery_signal",
        entity_id=signal.id,
        action=AuditAction.REVIEW,
        actor=actor,
        payload={"decision": decision, "signal_kind": signal.signal_kind, "page_url": signal.page_url},
    )
    db.flush()
    return signal


def map_signal_to_control(db: Session, signal: DiscoverySignal, control_id, actor: str) -> EvidenceControlLink:
    if signal.review_status != CandidateReviewStatus.APPROVED.value or signal.evidence_id is None:
        raise DiscoveryEngineError("Only approved signals with evidence can be mapped", 400)
    control = db.get(ControlRecord, control_id)
    if control is None:
        raise DiscoveryEngineError("Control not found", 404)
    existing = db.scalar(
        select(EvidenceControlLink).where(
            EvidenceControlLink.evidence_id == signal.evidence_id,
            EvidenceControlLink.control_id == control.id,
        )
    )
    if existing is not None:
        raise DiscoveryEngineError("Evidence is already mapped to this control", 409)
    link = EvidenceControlLink(evidence_id=signal.evidence_id, control_id=control.id)
    db.add(link)
    db.flush()
    record_audit(
        db,
        entity_type="discovery_signal",
        entity_id=signal.id,
        action=AuditAction.MAP,
        actor=actor,
        payload={"control_id": str(control.id), "evidence_id": str(signal.evidence_id)},
    )
    return link


def _materialize_evidence(db: Session, signal: DiscoverySignal, actor: str) -> None:
    provenance = (
        f"url={signal.page_url}; hash={signal.content_hash}; "
        f"scanned_at={signal.created_at.isoformat() if signal.created_at else utc_now().isoformat()}; "
        f"signal_id={signal.id}; discovery=m5"
    )
    record = EvidenceRecord(
        title=signal.title[:200],
        description=signal.statement,
        evidence_type=EvidenceType.DOCUMENT.value,
        source_reference=signal.page_url,
        provenance=provenance,
        collected_at=utc_now(),
        owner=actor,
        status=EvidenceStatus.ACCEPTED.value,
        document_ref=str(signal.id),
        envelope={
            "source_url": signal.page_url,
            "content_hash": signal.content_hash,
            "signal_kind": signal.signal_kind,
            "quote": signal.quote,
            "synthetic": True,
            "legal_compliance_claim": False,
        },
        integrity_hash=signal.content_hash,
    )
    db.add(record)
    db.flush()
    signal.evidence_id = record.id
    record_audit(
        db,
        entity_type="evidence",
        entity_id=record.id,
        action=AuditAction.CREATE,
        actor=actor,
        payload={"source": "discovery_signal", "signal_id": str(signal.id), "url": signal.page_url},
    )


def _title_from_url(url: str) -> str:
    path = urlparse(url).path or "/"
    if path in {"", "/"}:
        return DEFAULT_TITLE
    return f"Discovered page {path}"[:200]
