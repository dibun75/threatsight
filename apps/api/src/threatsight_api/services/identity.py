from __future__ import annotations

from threatsight_api.assurance.engine import DEMO_ENVIRONMENT, DEMO_SYSTEM_NAME
from threatsight_api.domain.enums import RecordOrigin

KNOWLEDGE_SYSTEM_NAME = "Knowledge assistant demo"
SHOWCASE_DISPLAY_NAME = "Customer Support AI Assistant"
SHOWCASE_ORG = "Nordic Retail AS"
KNOWLEDGE_DISPLAY_NAME = "Knowledge assistant"

ORIGIN_LABELS = {
    RecordOrigin.SHOWCASE.value: "SHOWCASE / SYNTHETIC",
    RecordOrigin.TEST.value: "TEST",
    RecordOrigin.MANUAL.value: "USER / MANUAL",
    RecordOrigin.IMPORTED.value: "IMPORTED",
    RecordOrigin.OBSERVED.value: "OBSERVED",
}


def is_canonical_demo(name: str, environment: str) -> bool:
    return name == DEMO_SYSTEM_NAME and environment == DEMO_ENVIRONMENT


def is_knowledge_demo(name: str, environment: str) -> bool:
    return name == KNOWLEDGE_SYSTEM_NAME and environment == DEMO_ENVIRONMENT


def is_labelled_showcase(name: str, environment: str) -> bool:
    return is_canonical_demo(name, environment) or is_knowledge_demo(name, environment)


def display_name_for(name: str, environment: str) -> str:
    if is_canonical_demo(name, environment):
        return SHOWCASE_DISPLAY_NAME
    if is_knowledge_demo(name, environment):
        return KNOWLEDGE_DISPLAY_NAME
    return name


def organisation_for(name: str, environment: str) -> str | None:
    if is_labelled_showcase(name, environment):
        return SHOWCASE_ORG
    return None


def identity_for(system) -> dict:
    name = system.name
    environment = system.environment
    origin = getattr(system, "record_origin", None) or RecordOrigin.MANUAL.value
    if is_labelled_showcase(name, environment) and origin == RecordOrigin.MANUAL.value:
        origin = RecordOrigin.SHOWCASE.value
    return {
        "display_name": display_name_for(name, environment),
        "organisation": organisation_for(name, environment),
        "technical_identifier": name,
        "record_origin": origin,
        "origin_label": ORIGIN_LABELS.get(origin, origin),
        "labelled_synthetic": is_labelled_showcase(name, environment),
        "supporting_inventory": is_knowledge_demo(name, environment),
        "canonical_demo": is_canonical_demo(name, environment),
    }
