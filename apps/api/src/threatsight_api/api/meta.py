from fastapi import APIRouter

from threatsight_api.config import get_settings
from threatsight_api.domain.models import ASSURANCE_LOOP

router = APIRouter()


@router.get("/meta")
def meta() -> dict:
    settings = get_settings()
    return {
        "product": settings.product_name,
        "version": settings.product_version,
        "milestone": settings.milestone,
        "north_star": "AI assurance platform",
        "assurance_loop": list(ASSURANCE_LOOP),
    }


@router.get("/security/status")
def security_status() -> dict:
    settings = get_settings()
    return {
        "sandbox_default": settings.sandbox_default,
        "kill_switch": settings.kill_switch,
        "execution_engine": "ctrl002_tool_authorization",
        "llm_is_verdict_authority": False,
        "extraction_provider": settings.extraction_provider,
        "document_content_is_untrusted": True,
        "demo_agent_url": settings.demo_agent_url,
        "assurance_adapter": settings.assurance_adapter,
        "demo_site_url": settings.demo_site_url,
        "discovery_adapter": settings.discovery_adapter,
        "llm_may_authorize_fetch": False,
        "unrestricted_crawl": False,
        "llm_is_coverage_authority": False,
        "framework_catalog_complete": False,
        "llm_is_intel_authority": False,
        "intel_catalog_complete": False,
        "autonomous_attack": False,
        "exploitation_engine": False,
        "auth_mode": "shared_token" if (settings.api_token or "").strip() else "lab_open",
        "api_token_configured": bool((settings.api_token or "").strip()),
        "openapi_enabled": settings.openapi_enabled,
        "llm_authors_executive_summary": False,
        "showcase_synthetic_labelled": True,
        "llm_may_authorize": False,
        "runtime_firewall": False,
        "intelligence_provider": settings.intelligence_provider,
    }
