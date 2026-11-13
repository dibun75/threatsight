from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from threatsight_api.api.schemas import (
    CandidateMapIn,
    CandidateMappingOut,
    CandidateOut,
    CandidateProvenance,
    CandidateReviewIn,
    CandidateUpdate,
    DocumentDetail,
    DocumentOut,
    DocumentVersionDetail,
    DocumentVersionOut,
)
from threatsight_api.config import Settings
from threatsight_api.domain.enums import (
    AssuranceStatus,
    AuditAction,
    CandidateReviewStatus,
    CandidateType,
    DocumentStatus,
    EvidenceStatus,
    EvidenceType,
    ExtractionStatus,
    LifecycleStatus,
    MappingProposalAction,
    RequirementSourceType,
    RequirementStatus,
)
from threatsight_api.domain.extraction import ExtractionResult, utc_now
from threatsight_api.intelligence.ingest import DocumentIngestError, parse_document
from threatsight_api.intelligence.pipeline import run_extraction
from threatsight_api.intelligence.providers.registry import get_extraction_provider
from threatsight_api.persistence.models import (
    CandidateControlMapping,
    ControlRecord,
    DocumentVersion,
    EvidenceRecord,
    ExtractionCandidate,
    RequirementControlLink,
    RequirementRecord,
    SourceDocument,
)
from threatsight_api.services.audit import record_audit


class DocumentServiceError(ValueError):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


def ingest_bytes(
    db: Session,
    *,
    data: bytes,
    filename: str,
    title: str | None,
    actor: str,
    settings: Settings,
    document: SourceDocument | None = None,
) -> SourceDocument:
    if len(data) > settings.max_document_bytes:
        raise DocumentServiceError("Document exceeds maximum size", 413)
    if not data:
        raise DocumentServiceError("Empty document", 400)
    try:
        parsed = parse_document(data, filename)
    except DocumentIngestError as exc:
        raise DocumentServiceError(str(exc), 400) from exc

    if document is None:
        document = SourceDocument(
            title=(title or _title_from_filename(filename))[:200],
            status=DocumentStatus.PROCESSING.value,
            current_version=0,
            uploaded_by=actor,
        )
        db.add(document)
        db.flush()
        record_audit(
            db,
            entity_type="document",
            entity_id=document.id,
            action=AuditAction.CREATE,
            actor=actor,
            payload={"title": document.title, "filename": parsed.filename},
        )
    else:
        document.status = DocumentStatus.PROCESSING.value
        document.failure_reason = None

    duplicate = db.scalar(
        select(DocumentVersion).where(
            DocumentVersion.document_id == document.id,
            DocumentVersion.content_hash == parsed.content_hash,
        )
    )
    if duplicate is not None:
        raise DocumentServiceError("This document version already exists (duplicate content hash)", 409)

    version_number = document.current_version + 1
    version = DocumentVersion(
        document_id=document.id,
        version_number=version_number,
        original_filename=parsed.filename[:300],
        media_kind=parsed.media_kind,
        content_type=parsed.content_type,
        byte_size=parsed.byte_size,
        content_hash=parsed.content_hash,
        content=data,
        extracted_text=parsed.extracted_text,
        locations=[loc.model_dump() for loc in parsed.locations],
        page_count=parsed.page_count,
        extraction_status=ExtractionStatus.PENDING.value,
        uploaded_by=actor,
    )
    db.add(version)
    try:
        db.flush()
    except IntegrityError as exc:
        raise DocumentServiceError("This document version already exists (duplicate content hash)", 409) from exc

    document.current_version = version_number
    record_audit(
        db,
        entity_type="document",
        entity_id=document.id,
        action=AuditAction.VERSION,
        actor=actor,
        payload={
            "version_id": str(version.id),
            "version_number": version_number,
            "content_hash": parsed.content_hash,
            "media_kind": parsed.media_kind,
        },
    )

    try:
        provider = get_extraction_provider(settings)
        result = run_extraction(parsed, provider)
        _persist_candidates(db, document, version, result)
        version.extraction_status = ExtractionStatus.COMPLETED.value
        version.extraction_provider = result.provider
        version.extraction_model = result.model
        version.extracted_at = utc_now()
        version.extraction_warnings = result.warnings
        version.extraction_error = None
        document.status = DocumentStatus.READY.value
        document.failure_reason = None
        record_audit(
            db,
            entity_type="document",
            entity_id=document.id,
            action=AuditAction.EXTRACT,
            actor=actor,
            payload={
                "version_id": str(version.id),
                "version_number": version_number,
                "provider": result.provider,
                "model": result.model,
                "candidate_count": len(result.candidates),
                "warnings": result.warnings[:10],
            },
        )
        db.flush()
    except (ValueError, RuntimeError) as exc:
        version.extraction_status = ExtractionStatus.FAILED.value
        version.extraction_error = str(exc)[:2000]
        document.status = DocumentStatus.FAILED.value
        document.failure_reason = str(exc)[:2000]
        record_audit(
            db,
            entity_type="document",
            entity_id=document.id,
            action=AuditAction.EXTRACT,
            actor=actor,
            payload={"version_id": str(version.id), "error": version.extraction_error},
        )
    return document


def _persist_candidates(
    db: Session,
    document: SourceDocument,
    version: DocumentVersion,
    result: ExtractionResult,
) -> None:
    now = utc_now()
    for item in result.candidates:
        db.add(
            ExtractionCandidate(
                document_id=document.id,
                document_version_id=version.id,
                candidate_type=item.candidate_type,
                review_status=CandidateReviewStatus.PENDING.value,
                title=item.title,
                statement=item.statement,
                confidence=item.confidence,
                page=item.locator.page,
                section=item.locator.section,
                start_char=item.locator.start_char,
                end_char=item.locator.end_char,
                quote=item.locator.quote,
                extraction_provider=result.provider,
                extraction_model=result.model,
                extracted_at=now,
            )
        )


def _title_from_filename(filename: str) -> str:
    name = filename.rsplit("/", 1)[-1]
    stem = name.rsplit(".", 1)[0].replace("_", " ").replace("-", " ").strip()
    return stem[:200] or "Untitled document"


def list_documents(db: Session, limit: int, offset: int) -> list[DocumentOut]:
    rows = list(db.scalars(select(SourceDocument).order_by(SourceDocument.created_at).offset(offset).limit(limit)))
    return [document_to_out(db, row) for row in rows]


def document_to_out(db: Session, document: SourceDocument) -> DocumentOut:
    latest = _latest_version(db, document)
    count = db.scalar(
        select(func.count()).select_from(ExtractionCandidate).where(ExtractionCandidate.document_id == document.id)
    )
    return DocumentOut(
        id=document.id,
        title=document.title,
        status=document.status,
        current_version=document.current_version,
        failure_reason=document.failure_reason,
        uploaded_by=document.uploaded_by,
        latest_hash=latest.content_hash if latest else None,
        latest_media_kind=latest.media_kind if latest else None,
        candidate_count=int(count or 0),
        created_at=document.created_at,
        updated_at=document.updated_at,
    )


def document_detail(db: Session, document: SourceDocument) -> DocumentDetail:
    versions = list(
        db.scalars(
            select(DocumentVersion)
            .where(DocumentVersion.document_id == document.id)
            .order_by(DocumentVersion.version_number)
        )
    )
    candidates = list(
        db.scalars(
            select(ExtractionCandidate)
            .where(ExtractionCandidate.document_id == document.id)
            .order_by(ExtractionCandidate.created_at)
        )
    )
    base = document_to_out(db, document)
    return DocumentDetail(
        **base.model_dump(),
        versions=[version_to_out(item) for item in versions],
        candidates=[candidate_to_out(db, item) for item in candidates],
    )


def version_to_out(version: DocumentVersion) -> DocumentVersionOut:
    warnings = version.extraction_warnings if isinstance(version.extraction_warnings, list) else []
    return DocumentVersionOut(
        id=version.id,
        document_id=version.document_id,
        version_number=version.version_number,
        original_filename=version.original_filename,
        media_kind=version.media_kind,
        content_type=version.content_type,
        byte_size=version.byte_size,
        content_hash=version.content_hash,
        page_count=version.page_count,
        extraction_status=version.extraction_status,
        extraction_provider=version.extraction_provider,
        extraction_model=version.extraction_model,
        extracted_at=version.extracted_at,
        extraction_warnings=[str(item) for item in warnings],
        extraction_error=version.extraction_error,
        uploaded_by=version.uploaded_by,
        created_at=version.created_at,
    )


def version_detail(version: DocumentVersion) -> DocumentVersionDetail:
    base = version_to_out(version)
    locations = version.locations if isinstance(version.locations, list) else []
    return DocumentVersionDetail(**base.model_dump(), extracted_text=version.extracted_text, locations=locations)


def candidate_to_out(db: Session, candidate: ExtractionCandidate) -> CandidateOut:
    version = db.get(DocumentVersion, candidate.document_version_id)
    document = db.get(SourceDocument, candidate.document_id)
    if version is None or document is None:
        raise DocumentServiceError("Candidate provenance is incomplete", 500)
    return CandidateOut(
        id=candidate.id,
        document_id=candidate.document_id,
        document_version_id=candidate.document_version_id,
        version_number=version.version_number,
        candidate_type=candidate.candidate_type,
        review_status=candidate.review_status,
        title=candidate.title,
        statement=candidate.statement,
        confidence=candidate.confidence,
        provenance=CandidateProvenance(
            document_id=document.id,
            document_title=document.title,
            document_version_id=version.id,
            version_number=version.version_number,
            content_hash=version.content_hash,
            page=candidate.page,
            section=candidate.section,
            start_char=candidate.start_char,
            end_char=candidate.end_char,
            quote=candidate.quote,
            extracted_at=candidate.extracted_at,
            extraction_method=candidate.extraction_provider,
            extraction_model=candidate.extraction_model,
        ),
        reviewer=candidate.reviewer,
        review_comment=candidate.review_comment,
        reviewed_at=candidate.reviewed_at,
        authoritative_requirement_id=candidate.authoritative_requirement_id,
        authoritative_control_id=candidate.authoritative_control_id,
        authoritative_evidence_id=candidate.authoritative_evidence_id,
        created_at=candidate.created_at,
        updated_at=candidate.updated_at,
    )


def update_candidate(db: Session, candidate: ExtractionCandidate, body: CandidateUpdate, actor: str) -> ExtractionCandidate:
    if candidate.review_status not in {
        CandidateReviewStatus.PENDING.value,
        CandidateReviewStatus.NEEDS_REVISION.value,
    }:
        raise DocumentServiceError("Only pending or needs_revision candidates can be edited", 409)
    data = body.model_dump(exclude_unset=True)
    before = {}
    after = {}
    for key, value in data.items():
        previous = getattr(candidate, key)
        if previous != value:
            before[key] = previous
            after[key] = value
            setattr(candidate, key, value)
    if candidate.review_status == CandidateReviewStatus.NEEDS_REVISION.value:
        candidate.review_status = CandidateReviewStatus.PENDING.value
        after["review_status"] = CandidateReviewStatus.PENDING.value
    if after:
        record_audit(
            db,
            entity_type="candidate",
            entity_id=candidate.id,
            action=AuditAction.UPDATE,
            actor=actor,
            payload={"before": before, "after": after, "document_id": str(candidate.document_id)},
        )
    return candidate


def review_candidate(db: Session, candidate: ExtractionCandidate, body: CandidateReviewIn, actor: str) -> ExtractionCandidate:
    if candidate.review_status == CandidateReviewStatus.APPROVED.value:
        raise DocumentServiceError("Candidate is already approved", 409)
    if candidate.review_status == CandidateReviewStatus.REJECTED.value:
        raise DocumentServiceError("Candidate is already rejected", 409)
    if body.title:
        candidate.title = body.title
    if body.statement:
        candidate.statement = body.statement
    decision = body.decision.value
    candidate.review_status = decision
    candidate.reviewer = actor
    candidate.review_comment = body.comment
    candidate.reviewed_at = utc_now()
    if decision == CandidateReviewStatus.APPROVED.value:
        _materialize_approved(db, candidate, actor)
    record_audit(
        db,
        entity_type="candidate",
        entity_id=candidate.id,
        action=AuditAction.REVIEW,
        actor=actor,
        payload={
            "decision": decision,
            "candidate_type": candidate.candidate_type,
            "document_id": str(candidate.document_id),
            "requirement_id": str(candidate.authoritative_requirement_id)
            if candidate.authoritative_requirement_id
            else None,
            "control_id": str(candidate.authoritative_control_id) if candidate.authoritative_control_id else None,
        },
    )
    record_audit(
        db,
        entity_type="document",
        entity_id=candidate.document_id,
        action=AuditAction.REVIEW,
        actor=actor,
        payload={"candidate_id": str(candidate.id), "decision": decision},
    )
    return candidate


def _materialize_approved(db: Session, candidate: ExtractionCandidate, actor: str) -> None:
    version = db.get(DocumentVersion, candidate.document_version_id)
    locator = _source_reference(candidate, version)
    if candidate.candidate_type == CandidateType.REQUIREMENT.value:
        record = RequirementRecord(
            title=candidate.title,
            statement=candidate.statement,
            source_type=RequirementSourceType.DOCUMENT.value,
            source_reference=locator,
            version=1,
            status=RequirementStatus.APPROVED.value,
        )
        db.add(record)
        db.flush()
        candidate.authoritative_requirement_id = record.id
        record_audit(
            db,
            entity_type="requirement",
            entity_id=record.id,
            action=AuditAction.CREATE,
            actor=actor,
            payload={"source": "document_candidate", "candidate_id": str(candidate.id), "status": record.status},
        )
    elif candidate.candidate_type == CandidateType.CONTROL.value:
        ident = _control_identifier_from_title(candidate.title)
        while db.scalar(select(ControlRecord).where(ControlRecord.identifier == ident)):
            ident = f"DOC-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(UTC)
        record = ControlRecord(
            identifier=ident,
            title=candidate.title[:200],
            objective=candidate.statement,
            description=f"Proposed from document candidate {candidate.id}",
            owner=actor,
            lifecycle=LifecycleStatus.DRAFT.value,
            version=1,
            assurance_status=AssuranceStatus.HUMAN_REVIEW_REQUIRED.value,
            assurance_rationale="Created from an approved document candidate. Not a legal conclusion.",
            assurance_set_by=actor,
            assurance_set_at=now,
        )
        db.add(record)
        db.flush()
        candidate.authoritative_control_id = record.id
        record_audit(
            db,
            entity_type="control",
            entity_id=record.id,
            action=AuditAction.CREATE,
            actor=actor,
            payload={
                "source": "document_candidate",
                "candidate_id": str(candidate.id),
                "identifier": ident,
                "assurance_status": record.assurance_status,
            },
        )
    elif candidate.candidate_type == CandidateType.EVIDENCE_STATEMENT.value:
        record = EvidenceRecord(
            title=candidate.title[:200],
            description=candidate.statement,
            evidence_type=EvidenceType.DOCUMENT.value,
            source_reference=locator,
            provenance=locator,
            owner=actor,
            status=EvidenceStatus.SUBMITTED.value,
            document_ref=str(candidate.document_id),
        )
        db.add(record)
        db.flush()
        candidate.authoritative_evidence_id = record.id
        record_audit(
            db,
            entity_type="evidence",
            entity_id=record.id,
            action=AuditAction.CREATE,
            actor=actor,
            payload={"source": "document_candidate", "candidate_id": str(candidate.id)},
        )
    elif candidate.candidate_type == CandidateType.AI_SYSTEM_REFERENCE.value:
        return


def map_candidate(db: Session, candidate: ExtractionCandidate, body: CandidateMapIn, actor: str) -> CandidateMappingOut:
    if candidate.review_status != CandidateReviewStatus.APPROVED.value:
        raise DocumentServiceError("Only approved candidates can be mapped", 409)
    if candidate.candidate_type != CandidateType.REQUIREMENT.value:
        raise DocumentServiceError("Control mapping is only available for approved requirement candidates", 409)
    if candidate.authoritative_requirement_id is None:
        raise DocumentServiceError("Approved requirement candidate is missing its governance record", 409)
    requirement_id = candidate.authoritative_requirement_id
    control_id = None
    link_id = None
    provenance = (
        f"document:{candidate.document_id}:v{candidate_to_out(db, candidate).version_number}"
        f":candidate:{candidate.id}:reviewer:{actor}"
    )[:500]

    if body.action == MappingProposalAction.REJECT:
        mapping = CandidateControlMapping(
            candidate_id=candidate.id,
            action=body.action.value,
            requirement_id=requirement_id,
            rationale=body.rationale,
            reviewer=actor,
            provenance=provenance,
        )
        db.add(mapping)
        db.flush()
        record_audit(
            db,
            entity_type="candidate",
            entity_id=candidate.id,
            action=AuditAction.UNMAP,
            actor=actor,
            payload={"action": body.action.value, "requirement_id": str(requirement_id)},
        )
        return _mapping_out(mapping)

    if body.action == MappingProposalAction.LINK_EXISTING:
        if body.control_id is None:
            raise DocumentServiceError("control_id is required to link an existing control", 400)
        control = db.get(ControlRecord, body.control_id)
        if control is None:
            raise DocumentServiceError("Control not found", 404)
        control_id = control.id
        link = RequirementControlLink(
            requirement_id=requirement_id,
            control_id=control.id,
            rationale=body.rationale,
            provenance=provenance,
        )
        db.add(link)
        try:
            db.flush()
        except IntegrityError as exc:
            raise DocumentServiceError("Mapping already exists", 409) from exc
        link_id = link.id
    elif body.action == MappingProposalAction.PROPOSE_NEW:
        if body.new_control is None:
            raise DocumentServiceError("new_control is required to propose a control", 400)
        proposed = body.new_control
        ident = proposed.identifier or f"DOC-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(UTC)
        control = ControlRecord(
            identifier=ident,
            title=proposed.title,
            objective=proposed.objective,
            description=proposed.description,
            owner=proposed.owner,
            lifecycle=LifecycleStatus.DRAFT.value,
            version=1,
            severity=proposed.severity.value if proposed.severity else None,
            assurance_status=AssuranceStatus.HUMAN_REVIEW_REQUIRED.value,
            assurance_rationale="Proposed from an approved document requirement. Not a legal conclusion.",
            assurance_set_by=actor,
            assurance_set_at=now,
        )
        db.add(control)
        try:
            db.flush()
        except IntegrityError as exc:
            raise DocumentServiceError("Control identifier already exists", 409) from exc
        control_id = control.id
        record_audit(
            db,
            entity_type="control",
            entity_id=control.id,
            action=AuditAction.CREATE,
            actor=actor,
            payload={"source": "document_mapping", "candidate_id": str(candidate.id), "identifier": ident},
        )
        link = RequirementControlLink(
            requirement_id=requirement_id,
            control_id=control.id,
            rationale=body.rationale,
            provenance=provenance,
        )
        db.add(link)
        db.flush()
        link_id = link.id
    else:
        raise DocumentServiceError("Unknown mapping action", 400)

    mapping = CandidateControlMapping(
        candidate_id=candidate.id,
        action=body.action.value,
        control_id=control_id,
        requirement_id=requirement_id,
        mapping_link_id=link_id,
        rationale=body.rationale,
        reviewer=actor,
        provenance=provenance,
    )
    db.add(mapping)
    db.flush()
    record_audit(
        db,
        entity_type="mapping",
        entity_id=link_id,
        action=AuditAction.MAP,
        actor=actor,
        payload={
            "candidate_id": str(candidate.id),
            "requirement_id": str(requirement_id),
            "control_id": str(control_id),
            "informational_only": True,
            "provenance": provenance,
        },
    )
    record_audit(
        db,
        entity_type="document",
        entity_id=candidate.document_id,
        action=AuditAction.MAP,
        actor=actor,
        payload={"candidate_id": str(candidate.id), "control_id": str(control_id), "action": body.action.value},
    )
    return _mapping_out(mapping)


def _mapping_out(mapping: CandidateControlMapping) -> CandidateMappingOut:
    return CandidateMappingOut(
        id=mapping.id,
        candidate_id=mapping.candidate_id,
        action=mapping.action,
        control_id=mapping.control_id,
        requirement_id=mapping.requirement_id,
        mapping_link_id=mapping.mapping_link_id,
        rationale=mapping.rationale,
        reviewer=mapping.reviewer,
        provenance=mapping.provenance,
        created_at=mapping.created_at,
    )


def _latest_version(db: Session, document: SourceDocument) -> DocumentVersion | None:
    return db.scalar(
        select(DocumentVersion)
        .where(DocumentVersion.document_id == document.id)
        .order_by(DocumentVersion.version_number.desc())
        .limit(1)
    )


def _source_reference(candidate: ExtractionCandidate, version: DocumentVersion | None) -> str:
    page = f"page={candidate.page}" if candidate.page is not None else "page=none"
    version_number = version.version_number if version else "?"
    digest = version.content_hash if version else "unknown"
    return f"document:{candidate.document_id}:v{version_number}:{page}:hash={digest}"[:500]


def _control_identifier_from_title(title: str) -> str:
    compact = "".join(ch for ch in title.upper() if ch.isalnum() or ch in "-_")[:24]
    if compact.startswith("CTRL"):
        ident = compact if compact[0].isalpha() else f"C{compact}"
        if 3 <= len(ident) <= 32:
            return ident
    return f"DOC-{uuid.uuid4().hex[:8].upper()}"
