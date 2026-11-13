from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Response
from fastapi.encoders import jsonable_encoder
from sqlalchemy import select

from threatsight_api.api.deps import DbSession, WorkspaceScope
from threatsight_api.persistence.models import (
    BusinessService,
    RadarReadinessLink,
    RadarSavedView,
    RadarTriage,
    RadarWorkflowAudit,
    ThreatClusterMembership,
    ThreatRelevance,
    WorkspaceResourceBinding,
)
from threatsight_api.radar.contracts import (
    BusinessServiceIn,
    ReadinessLinkIn,
    SavedViewIn,
    TriageIn,
)

router = APIRouter(prefix="/radar", tags=["radar-workflows"])
WRITE_ROLES = {"operator", "workspace-admin", "platform-admin"}


def _require_write(scope: WorkspaceScope) -> None:
    if scope.role not in WRITE_ROLES:
        raise HTTPException(status_code=403, detail="Workspace role is read-only")


def _audit(db: DbSession, scope: WorkspaceScope, entity_type: str, entity_id, action: str, payload: dict) -> None:
    db.add(
        RadarWorkflowAudit(
            workspace_id=scope.id,
            entity_type=entity_type,
            entity_id=entity_id,
            action=action,
            actor=scope.subject,
            payload=jsonable_encoder(payload),
        )
    )


def _subject_visible(
    db: DbSession,
    scope: WorkspaceScope,
    subject_type: Literal["event", "cluster"],
    subject_id: uuid.UUID,
) -> bool:
    if subject_type == "event":
        return db.scalar(
            select(ThreatRelevance.id).where(
                ThreatRelevance.workspace_id == scope.id,
                ThreatRelevance.event_id == subject_id,
            )
        ) is not None
    return db.scalar(
        select(ThreatClusterMembership.id)
        .join(ThreatRelevance, ThreatRelevance.event_id == ThreatClusterMembership.event_id)
        .where(
            ThreatRelevance.workspace_id == scope.id,
            ThreatClusterMembership.cluster_id == subject_id,
        )
        .limit(1)
    ) is not None


def _view_out(item: RadarSavedView) -> dict:
    return {
        "id": str(item.id),
        "name": item.name,
        "filters": item.filters,
        "created_by": item.created_by,
        "updated_by": item.updated_by,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }


@router.get("/saved-views")
def list_saved_views(db: DbSession, scope: WorkspaceScope) -> list[dict]:
    return [
        _view_out(item)
        for item in db.scalars(
            select(RadarSavedView)
            .where(RadarSavedView.workspace_id == scope.id)
            .order_by(RadarSavedView.name)
        )
    ]


@router.post("/saved-views", status_code=201)
def create_saved_view(body: SavedViewIn, db: DbSession, scope: WorkspaceScope) -> dict:
    _require_write(scope)
    exists = db.scalar(
        select(RadarSavedView.id).where(
            RadarSavedView.workspace_id == scope.id,
            RadarSavedView.name == body.name,
        )
    )
    if exists:
        raise HTTPException(status_code=409, detail="Saved-view name already exists")
    item = RadarSavedView(
        workspace_id=scope.id,
        name=body.name,
        filters=body.filters.model_dump(mode="json", exclude_none=True),
        created_by=scope.subject,
        updated_by=scope.subject,
    )
    db.add(item)
    db.flush()
    _audit(db, scope, "saved_view", item.id, "created", _view_out(item))
    return _view_out(item)


@router.get("/saved-views/{view_id}")
def get_saved_view(view_id: uuid.UUID, db: DbSession, scope: WorkspaceScope) -> dict:
    item = db.scalar(
        select(RadarSavedView).where(
            RadarSavedView.id == view_id,
            RadarSavedView.workspace_id == scope.id,
        )
    )
    if item is None:
        raise HTTPException(status_code=404, detail="Saved view not found")
    return _view_out(item)


@router.put("/saved-views/{view_id}")
def update_saved_view(
    view_id: uuid.UUID,
    body: SavedViewIn,
    db: DbSession,
    scope: WorkspaceScope,
) -> dict:
    _require_write(scope)
    item = db.scalar(
        select(RadarSavedView).where(
            RadarSavedView.id == view_id,
            RadarSavedView.workspace_id == scope.id,
        )
    )
    if item is None:
        raise HTTPException(status_code=404, detail="Saved view not found")
    duplicate = db.scalar(
        select(RadarSavedView.id).where(
            RadarSavedView.workspace_id == scope.id,
            RadarSavedView.name == body.name,
            RadarSavedView.id != view_id,
        )
    )
    if duplicate:
        raise HTTPException(status_code=409, detail="Saved-view name already exists")
    item.name = body.name
    item.filters = body.filters.model_dump(mode="json", exclude_none=True)
    item.updated_by = scope.subject
    _audit(db, scope, "saved_view", item.id, "updated", _view_out(item))
    return _view_out(item)


@router.delete("/saved-views/{view_id}", status_code=204)
def delete_saved_view(
    view_id: uuid.UUID,
    db: DbSession,
    scope: WorkspaceScope,
) -> Response:
    _require_write(scope)
    item = db.scalar(
        select(RadarSavedView).where(
            RadarSavedView.id == view_id,
            RadarSavedView.workspace_id == scope.id,
        )
    )
    if item is None:
        raise HTTPException(status_code=404, detail="Saved view not found")
    _audit(db, scope, "saved_view", item.id, "deleted", _view_out(item))
    db.delete(item)
    return Response(status_code=204)


def _triage_out(item: RadarTriage) -> dict:
    return {
        "id": str(item.id),
        "subject_type": item.subject_type,
        "subject_id": str(item.subject_id),
        "status": item.status,
        "priority": item.priority,
        "owner": item.owner,
        "due_at": item.due_at,
        "rationale": item.rationale,
        "actor": item.actor,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }


@router.get("/triage/{subject_type}/{subject_id}")
def get_triage(
    subject_type: Literal["event", "cluster"],
    subject_id: uuid.UUID,
    db: DbSession,
    scope: WorkspaceScope,
) -> dict:
    item = db.scalar(
        select(RadarTriage).where(
            RadarTriage.workspace_id == scope.id,
            RadarTriage.subject_type == subject_type,
            RadarTriage.subject_id == subject_id,
        )
    )
    if item is None:
        raise HTTPException(status_code=404, detail="Triage record not found")
    return _triage_out(item)


@router.put("/triage/{subject_type}/{subject_id}")
def put_triage(
    subject_type: Literal["event", "cluster"],
    subject_id: uuid.UUID,
    body: TriageIn,
    db: DbSession,
    scope: WorkspaceScope,
) -> dict:
    _require_write(scope)
    if not _subject_visible(db, scope, subject_type, subject_id):
        raise HTTPException(status_code=404, detail="Radar subject not found")
    item = db.scalar(
        select(RadarTriage).where(
            RadarTriage.workspace_id == scope.id,
            RadarTriage.subject_type == subject_type,
            RadarTriage.subject_id == subject_id,
        )
    )
    action = "updated"
    if item is None:
        action = "created"
        item = RadarTriage(
            workspace_id=scope.id,
            subject_type=subject_type,
            subject_id=subject_id,
        )
        db.add(item)
    for field, value in body.model_dump().items():
        setattr(item, field, value)
    item.actor = scope.subject
    db.flush()
    output = _triage_out(item)
    _audit(db, scope, "triage", item.id, action, output)
    return output


@router.get("/resources")
def list_linkable_resources(
    db: DbSession,
    scope: WorkspaceScope,
    resource_type: Literal["control", "evidence", "system", "business_service"] | None = None,
) -> list[dict]:
    resources: list[dict] = []
    if resource_type in (None, "control", "evidence", "system"):
        statement = select(WorkspaceResourceBinding).where(
            WorkspaceResourceBinding.workspace_id == scope.id
        )
        if resource_type:
            statement = statement.where(
                WorkspaceResourceBinding.resource_type == resource_type
            )
        resources.extend(
            {
                "type": item.resource_type,
                "id": str(item.resource_id),
                "label": item.label,
                "boundary": "explicit_workspace_binding",
            }
            for item in db.scalars(statement.order_by(WorkspaceResourceBinding.label))
        )
    if resource_type in (None, "business_service"):
        resources.extend(
            {
                "type": "business_service",
                "id": str(item.id),
                "label": item.name,
                "boundary": "workspace_owned",
            }
            for item in db.scalars(
                select(BusinessService)
                .where(BusinessService.workspace_id == scope.id)
                .order_by(BusinessService.name)
            )
        )
    return resources


@router.post("/business-services", status_code=201)
def create_business_service(
    body: BusinessServiceIn,
    db: DbSession,
    scope: WorkspaceScope,
) -> dict:
    _require_write(scope)
    duplicate = db.scalar(
        select(BusinessService.id).where(
            BusinessService.workspace_id == scope.id,
            BusinessService.key == body.key,
        )
    )
    if duplicate:
        raise HTTPException(status_code=409, detail="Business-service key already exists")
    item = BusinessService(workspace_id=scope.id, **body.model_dump())
    db.add(item)
    db.flush()
    output = {"id": str(item.id), **body.model_dump()}
    _audit(db, scope, "business_service", item.id, "created", output)
    return output


def _link_out(item: RadarReadinessLink) -> dict:
    return {
        "id": str(item.id),
        "subject_type": item.subject_type,
        "subject_id": str(item.subject_id),
        "target_type": item.target_type,
        "target_id": str(item.target_id),
        "reason": item.reason,
        "provenance": item.provenance,
        "limitations": item.limitations,
        "actor": item.actor,
        "created_at": item.created_at,
    }


@router.get("/links/{subject_type}/{subject_id}")
def list_readiness_links(
    subject_type: Literal["event", "cluster"],
    subject_id: uuid.UUID,
    db: DbSession,
    scope: WorkspaceScope,
) -> list[dict]:
    if not _subject_visible(db, scope, subject_type, subject_id):
        raise HTTPException(status_code=404, detail="Radar subject not found")
    return [
        _link_out(item)
        for item in db.scalars(
            select(RadarReadinessLink).where(
                RadarReadinessLink.workspace_id == scope.id,
                RadarReadinessLink.subject_type == subject_type,
                RadarReadinessLink.subject_id == subject_id,
            )
        )
    ]


@router.post("/links/{subject_type}/{subject_id}", status_code=201)
def create_readiness_link(
    subject_type: Literal["event", "cluster"],
    subject_id: uuid.UUID,
    body: ReadinessLinkIn,
    db: DbSession,
    scope: WorkspaceScope,
) -> dict:
    _require_write(scope)
    if not _subject_visible(db, scope, subject_type, subject_id):
        raise HTTPException(status_code=404, detail="Radar subject not found")
    if body.target_type == "business_service":
        target_exists = db.scalar(
            select(BusinessService.id).where(
                BusinessService.id == body.target_id,
                BusinessService.workspace_id == scope.id,
            )
        )
    else:
        target_exists = db.scalar(
            select(WorkspaceResourceBinding.id).where(
                WorkspaceResourceBinding.workspace_id == scope.id,
                WorkspaceResourceBinding.resource_type == body.target_type,
                WorkspaceResourceBinding.resource_id == body.target_id,
            )
        )
    if target_exists is None:
        raise HTTPException(status_code=404, detail="Workspace-bound target not found")
    duplicate = db.scalar(
        select(RadarReadinessLink.id).where(
            RadarReadinessLink.workspace_id == scope.id,
            RadarReadinessLink.subject_type == subject_type,
            RadarReadinessLink.subject_id == subject_id,
            RadarReadinessLink.target_type == body.target_type,
            RadarReadinessLink.target_id == body.target_id,
        )
    )
    if duplicate:
        raise HTTPException(status_code=409, detail="Readiness link already exists")
    item = RadarReadinessLink(
        workspace_id=scope.id,
        subject_type=subject_type,
        subject_id=subject_id,
        actor=scope.subject,
        **body.model_dump(),
    )
    db.add(item)
    db.flush()
    output = _link_out(item)
    _audit(db, scope, "readiness_link", item.id, "created", output)
    return output


@router.delete("/links/{link_id}", status_code=204)
def delete_readiness_link(
    link_id: uuid.UUID,
    db: DbSession,
    scope: WorkspaceScope,
) -> Response:
    _require_write(scope)
    item = db.scalar(
        select(RadarReadinessLink).where(
            RadarReadinessLink.id == link_id,
            RadarReadinessLink.workspace_id == scope.id,
        )
    )
    if item is None:
        raise HTTPException(status_code=404, detail="Readiness link not found")
    _audit(db, scope, "readiness_link", item.id, "deleted", _link_out(item))
    db.delete(item)
    return Response(status_code=204)


@router.get("/workflow-audit")
def list_workflow_audit(
    db: DbSession,
    scope: WorkspaceScope,
    limit: int = Query(default=100, ge=1, le=200),
) -> list[dict]:
    return [
        {
            "id": str(item.id),
            "entity_type": item.entity_type,
            "entity_id": str(item.entity_id),
            "action": item.action,
            "actor": item.actor,
            "at": item.at,
            "payload": item.payload,
        }
        for item in db.scalars(
            select(RadarWorkflowAudit)
            .where(RadarWorkflowAudit.workspace_id == scope.id)
            .order_by(RadarWorkflowAudit.at.desc())
            .limit(limit)
        )
    ]
