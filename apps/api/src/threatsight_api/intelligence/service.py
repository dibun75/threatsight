from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from threatsight_api.config import Settings, get_settings
from threatsight_api.domain.enums import AuditAction
from threatsight_api.domain.intelligence import PROMPT_VERSION, TASK_VERSIONS
from threatsight_api.intelligence.explain import collect_facts, heuristic_explain, merge_llm_explain
from threatsight_api.intelligence.llm import complete_task, llm_configured
from threatsight_api.persistence.models import AISystemRecord, IntelligenceRun
from threatsight_api.services.audit import record_audit


def explain_system(
    db: Session,
    settings: Settings,
    system: AISystemRecord,
    actor: str,
    *,
    persist: bool = False,
    use_llm: bool = False,
) -> dict:
    heuristic = heuristic_explain(db, system)
    available = llm_configured(settings)
    payload = heuristic
    provider_name = heuristic["provider"]
    model = heuristic["model"]
    authored = False
    if use_llm:
        facts = collect_facts(db, system)
        llm_payload = {
            "facts": {
                "statements": facts["statements"],
                "missing": facts["missing"],
                "recommended_action": facts["recommended_action"],
                "confidence": facts["confidence"],
                "uncertainty": facts["uncertainty"],
                "fact_ids": list(facts["facts"]),
            }
        }
        output, provider, used_llm = complete_task(settings, "explain_posture", llm_payload)
        provider_name = provider.name
        model = provider.model
        authored = used_llm
        if used_llm:
            payload = merge_llm_explain(heuristic, output, facts["facts"])
            payload["provider"] = provider.name
            payload["model"] = provider.model
    payload["llm_available"] = available
    payload["llm_authored"] = authored
    payload["legal_compliance_claim"] = False
    payload["never_authorizes"] = True
    payload["verdict_authority"] = "deterministic_policy"
    if persist:
        _persist(
            db,
            actor,
            task="explain_posture",
            provider=provider_name,
            model=model,
            source_type="ai_system",
            source_id=system.id,
            output=payload,
            confidence=payload.get("confidence"),
            uncertainty=payload.get("uncertainty"),
            llm_available=available,
            llm_authored=authored,
        )
    return payload


def run_task(
    db: Session,
    settings: Settings,
    actor: str,
    *,
    task: str,
    system: AISystemRecord | None,
    persist: bool = True,
) -> dict:
    facts = collect_facts(db, system) if system is not None else {"missing": ["ai_system"], "facts": {}}
    output, provider, used_llm = complete_task(settings, task, {"facts": facts})
    output["legal_compliance_claim"] = False
    output["never_authorizes"] = True
    output["verdict_authority"] = "deterministic_policy"
    output["llm_authored"] = used_llm
    output["llm_available"] = llm_configured(settings)
    output["provider"] = provider.name
    output["model"] = provider.model
    output["prompt_version"] = TASK_VERSIONS.get(task, PROMPT_VERSION)
    if persist:
        _persist(
            db,
            actor,
            task=task,
            provider=provider.name,
            model=provider.model,
            source_type="ai_system" if system is not None else "none",
            source_id=system.id if system is not None else None,
            output=output,
            confidence=output.get("confidence"),
            uncertainty=output.get("uncertainty"),
            llm_available=output["llm_available"],
            llm_authored=used_llm,
        )
    return output


def intelligence_status(settings: Settings | None = None) -> dict:
    cfg = settings or get_settings()
    return {
        "provider": (cfg.intelligence_provider or "heuristic").strip().lower(),
        "llm_available": llm_configured(cfg),
        "llm_is_verdict_authority": False,
        "llm_may_authorize": False,
        "legal_compliance_claim": False,
        "runtime_firewall": False,
        "autonomous_attack": False,
        "prompt_version": PROMPT_VERSION,
        "tasks": list(TASK_VERSIONS),
        "rate_limit_per_minute": 20,
        "secrets_persisted": False,
    }


def _persist(
    db: Session,
    actor: str,
    *,
    task: str,
    provider: str,
    model: str,
    source_type: str,
    source_id: uuid.UUID | None,
    output: dict,
    confidence,
    uncertainty,
    llm_available: bool,
    llm_authored: bool,
) -> IntelligenceRun:
    run = IntelligenceRun(
        task=task,
        provider=provider,
        model=model,
        source_type=source_type,
        source_id=source_id,
        prompt_version=TASK_VERSIONS.get(task, PROMPT_VERSION),
        output=output,
        confidence=confidence,
        uncertainty=uncertainty,
        legal_compliance_claim=False,
        actor=actor,
        llm_available=llm_available,
        llm_authored=llm_authored,
    )
    db.add(run)
    db.flush()
    record_audit(
        db,
        entity_type="intelligence_run",
        entity_id=run.id,
        action=AuditAction.EXTRACT,
        actor=actor,
        payload={
            "task": task,
            "provider": provider,
            "model": model,
            "llm_authored": llm_authored,
            "legal_compliance_claim": False,
            "never_authorizes": True,
        },
    )
    return run
