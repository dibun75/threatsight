from __future__ import annotations

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from threatsight_api.api.deps import Actor, DbSession
from threatsight_api.api.schemas import ControlOut, FrameworkMapOut, FrameworkReferenceOut
from threatsight_api.api.systems import _framework_map_out
from threatsight_api.frameworks.catalog import CATALOG_VERSION, meta_for
from threatsight_api.frameworks.engine import (
    bootstrap_frameworks,
    load_framework_summaries,
    load_item_coverage,
)
from threatsight_api.persistence.models import ControlFrameworkLink, FrameworkReference

router = APIRouter(prefix="/frameworks", tags=["frameworks"])


def _reference_out(record: FrameworkReference) -> FrameworkReferenceOut:
    return FrameworkReferenceOut(
        id=record.id,
        framework_key=record.framework_key,
        reference_code=record.reference_code,
        title=record.title,
        locator=record.locator,
        statement=record.statement,
        source_kind=record.source_kind,
        catalog_version=record.catalog_version,
        informational_only=bool(record.informational_only),
        legal_compliance_claim=False,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.post("/demo/bootstrap")
def bootstrap(db: DbSession, actor: Actor) -> dict:
    return bootstrap_frameworks(db, actor)


@router.get("/status")
def framework_status(db: DbSession) -> dict:
    summaries = load_framework_summaries(db)
    return {
        "catalog_version": CATALOG_VERSION,
        "catalog_complete": False,
        "legal_compliance_claim": False,
        "llm_is_coverage_authority": False,
        "frameworks": len(summaries),
        "items": sum(item["item_count"] for item in summaries),
        "mapped_items": sum(item["mapped_items"] for item in summaries),
    }


@router.get("")
def list_frameworks(db: DbSession) -> list[dict]:
    return load_framework_summaries(db)


@router.get("/{framework_key}")
def get_framework(framework_key: str, db: DbSession) -> dict:
    meta = meta_for(framework_key)
    if meta is None:
        raise HTTPException(status_code=404, detail="Unknown framework")
    rows = list(
        db.scalars(
            select(FrameworkReference)
            .where(FrameworkReference.framework_key == framework_key)
            .order_by(FrameworkReference.reference_code)
        )
    )
    items = []
    for record in rows:
        coverage = load_item_coverage(db, record)
        items.append(
            {
                **_reference_out(record).model_dump(mode="json"),
                "mapped": coverage["mapped"],
                "coverage_status": coverage["coverage_status"],
                "control_count": coverage["control_count"],
            }
        )
    summary = next(item for item in load_framework_summaries(db) if item["key"] == framework_key)
    return {**summary, "items": items}


@router.get("/{framework_key}/items/{reference_code}")
def get_framework_item(framework_key: str, reference_code: str, db: DbSession) -> dict:
    record = db.scalar(
        select(FrameworkReference).where(
            FrameworkReference.framework_key == framework_key,
            FrameworkReference.reference_code == reference_code,
        )
    )
    if record is None:
        raise HTTPException(status_code=404, detail="Framework item not found")
    coverage = load_item_coverage(db, record)
    links = list(
        db.scalars(
            select(ControlFrameworkLink).where(ControlFrameworkLink.framework_reference_id == record.id)
        )
    )
    mappings: list[FrameworkMapOut] = [_framework_map_out(link, record) for link in links]
    return {
        **_reference_out(record).model_dump(mode="json"),
        "mapped": coverage["mapped"],
        "coverage_status": coverage["coverage_status"],
        "legal_compliance_claim": False,
        "catalog_complete": False,
        "controls": [ControlOut.model_validate(item) for item in coverage["controls"]],
        "mappings": mappings,
    }
