from __future__ import annotations

import uuid

from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from sqlalchemy import select

from threatsight_api.api.deps import Actor, DbSession, Limit, Offset, require_entity
from threatsight_api.api.schemas import (
    CandidateMapIn,
    CandidateMappingOut,
    CandidateOut,
    CandidateReviewIn,
    CandidateUpdate,
    DocumentDetail,
    DocumentOut,
    DocumentVersionDetail,
    DocumentVersionOut,
)
from threatsight_api.config import get_settings
from threatsight_api.persistence.models import DocumentVersion, ExtractionCandidate, SourceDocument
from threatsight_api.services.documents import (
    DocumentServiceError,
    candidate_to_out,
    document_detail,
    ingest_bytes,
    list_documents,
    map_candidate,
    review_candidate,
    update_candidate,
    version_detail,
    version_to_out,
)
from threatsight_api.services.scope import resolve_list_scope

documents_router = APIRouter(prefix="/documents", tags=["documents"])
candidates_router = APIRouter(prefix="/candidates", tags=["candidates"])


def _raise_service(exc: DocumentServiceError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@documents_router.post("", status_code=201, response_model=DocumentDetail)
def upload_document(
    db: DbSession,
    actor: Actor,
    file: UploadFile = File(...),
    title: str | None = Form(default=None),
) -> DocumentDetail:
    settings = get_settings()
    data = _read_upload(file, settings.max_document_bytes)
    filename = file.filename or "upload.txt"
    try:
        document = ingest_bytes(
            db,
            data=data,
            filename=filename,
            title=title,
            actor=actor,
            settings=settings,
        )
    except DocumentServiceError as exc:
        _raise_service(exc)
    return document_detail(db, document)


@documents_router.get("", response_model=list[DocumentOut])
def list_source_documents(
    db: DbSession,
    limit: Limit = 50,
    offset: Offset = 0,
    scope: Annotated[str | None, Query(max_length=16)] = None,
) -> list[DocumentOut]:
    resolved, _system_ids = resolve_list_scope(db, scope)
    if resolved == "showcase":
        return []
    return list_documents(db, limit, offset)


@documents_router.get("/{document_id}", response_model=DocumentDetail)
def get_document(document_id: uuid.UUID, db: DbSession) -> DocumentDetail:
    document = require_entity(db, SourceDocument, document_id, "Document")
    return document_detail(db, document)


@documents_router.post("/{document_id}/versions", status_code=201, response_model=DocumentDetail)
def upload_version(
    document_id: uuid.UUID,
    db: DbSession,
    actor: Actor,
    file: UploadFile = File(...),
) -> DocumentDetail:
    document = require_entity(db, SourceDocument, document_id, "Document")
    settings = get_settings()
    data = _read_upload(file, settings.max_document_bytes)
    filename = file.filename or "upload.txt"
    try:
        ingest_bytes(
            db,
            data=data,
            filename=filename,
            title=None,
            actor=actor,
            settings=settings,
            document=document,
        )
    except DocumentServiceError as exc:
        _raise_service(exc)
    return document_detail(db, document)


@documents_router.get("/{document_id}/versions", response_model=list[DocumentVersionOut])
def list_versions(document_id: uuid.UUID, db: DbSession) -> list[DocumentVersionOut]:
    require_entity(db, SourceDocument, document_id, "Document")
    rows = list(
        db.scalars(
            select(DocumentVersion)
            .where(DocumentVersion.document_id == document_id)
            .order_by(DocumentVersion.version_number)
        )
    )
    return [version_to_out(item) for item in rows]


@documents_router.get("/{document_id}/versions/{version_id}", response_model=DocumentVersionDetail)
def get_version(document_id: uuid.UUID, version_id: uuid.UUID, db: DbSession) -> DocumentVersionDetail:
    require_entity(db, SourceDocument, document_id, "Document")
    version = require_entity(db, DocumentVersion, version_id, "Document version")
    if version.document_id != document_id:
        raise HTTPException(status_code=404, detail="Document version not found")
    return version_detail(version)


@documents_router.get("/{document_id}/candidates", response_model=list[CandidateOut])
def list_document_candidates(
    document_id: uuid.UUID,
    db: DbSession,
    version_id: uuid.UUID | None = None,
) -> list[CandidateOut]:
    require_entity(db, SourceDocument, document_id, "Document")
    stmt = select(ExtractionCandidate).where(ExtractionCandidate.document_id == document_id)
    if version_id is not None:
        stmt = stmt.where(ExtractionCandidate.document_version_id == version_id)
    rows = list(db.scalars(stmt.order_by(ExtractionCandidate.created_at)))
    return [candidate_to_out(db, item) for item in rows]


@candidates_router.get("/{candidate_id}", response_model=CandidateOut)
def get_candidate(candidate_id: uuid.UUID, db: DbSession) -> CandidateOut:
    candidate = require_entity(db, ExtractionCandidate, candidate_id, "Candidate")
    return candidate_to_out(db, candidate)


@candidates_router.patch("/{candidate_id}", response_model=CandidateOut)
def patch_candidate(candidate_id: uuid.UUID, body: CandidateUpdate, db: DbSession, actor: Actor) -> CandidateOut:
    candidate = require_entity(db, ExtractionCandidate, candidate_id, "Candidate")
    try:
        update_candidate(db, candidate, body, actor)
    except DocumentServiceError as exc:
        _raise_service(exc)
    return candidate_to_out(db, candidate)


@candidates_router.post("/{candidate_id}/review", response_model=CandidateOut)
def post_candidate_review(
    candidate_id: uuid.UUID,
    body: CandidateReviewIn,
    db: DbSession,
    actor: Actor,
) -> CandidateOut:
    candidate = require_entity(db, ExtractionCandidate, candidate_id, "Candidate")
    try:
        review_candidate(db, candidate, body, actor)
    except DocumentServiceError as exc:
        _raise_service(exc)
    return candidate_to_out(db, candidate)


@candidates_router.post("/{candidate_id}/map-control", status_code=201, response_model=CandidateMappingOut)
def post_candidate_mapping(
    candidate_id: uuid.UUID,
    body: CandidateMapIn,
    db: DbSession,
    actor: Actor,
) -> CandidateMappingOut:
    candidate = require_entity(db, ExtractionCandidate, candidate_id, "Candidate")
    try:
        return map_candidate(db, candidate, body, actor)
    except DocumentServiceError as exc:
        _raise_service(exc)


@candidates_router.get("/{candidate_id}/citation", response_model=CandidateOut)
def get_candidate_citation(candidate_id: uuid.UUID, db: DbSession) -> CandidateOut:
    candidate = require_entity(db, ExtractionCandidate, candidate_id, "Candidate")
    return candidate_to_out(db, candidate)


def _read_upload(file: UploadFile, max_bytes: int) -> bytes:
    data = file.file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HTTPException(status_code=413, detail="Document exceeds maximum size")
    return data
