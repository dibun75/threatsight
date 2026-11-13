from __future__ import annotations

from dataclasses import dataclass

from threatsight_api.assurance.catalog import AUTH_01, AUTH_02

CATALOG_VERSION = "m13-2026-08"

OWASP_LLM = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
ATLAS = "https://atlas.mitre.org/"

SOURCE_KINDS = frozenset({"owasp", "atlas", "vendor", "incident", "lab", "nist"})


@dataclass(frozen=True)
class ThreatDef:
    key: str
    title: str
    statement: str


@dataclass(frozen=True)
class TechniqueDef:
    key: str
    threat_key: str
    title: str
    statement: str
    locator: str
    source_kind: str
    framework_key: str | None = None
    reference_code: str | None = None
    affected_capability: str = "unknown"


@dataclass(frozen=True)
class AdvisoryDef:
    key: str
    title: str
    summary: str
    locator: str
    source_kind: str
    technique_keys: tuple[str, ...]


@dataclass(frozen=True)
class TestSuggestionDef:
    technique_key: str
    scenario_key: str
    rationale: str


THREATS: tuple[ThreatDef, ...] = (
    ThreatDef(
        "prompt_injection",
        "Prompt injection",
        "Informational category: untrusted content may influence model instructions, including indirect injection. Not an exploit recipe.",
    ),
    ThreatDef(
        "tool_abuse",
        "Tool abuse",
        "Informational category: a model may request high-impact tools without authorization. Not an exploit recipe.",
    ),
    ThreatDef(
        "memory_poisoning",
        "Memory poisoning",
        "Informational category: untrusted data may enter memory or retrieval stores. Not an exploit recipe.",
    ),
    ThreatDef(
        "data_leakage",
        "Data leakage",
        "Informational category: sensitive information may be disclosed through model output. Not an exploit recipe.",
    ),
    ThreatDef(
        "privilege_escalation",
        "Agent privilege escalation",
        "Informational category: an agent may exceed intended privileges via tools (excessive agency). Not an exploit recipe.",
    ),
    ThreatDef(
        "cross_tenant",
        "Cross-tenant access",
        "Informational category: an agent may retrieve or act on another tenant's data. Not an exploit recipe.",
    ),
    ThreatDef(
        "mcp_poisoning",
        "MCP and tool poisoning",
        "Informational category: untrusted tool definitions or MCP servers may alter agent behavior. Not an exploit recipe.",
    ),
    ThreatDef(
        "oversight_bypass",
        "Human-oversight bypass",
        "Informational category: high-impact actions may complete without required human review. Not an exploit recipe.",
    ),
)

TECHNIQUES: tuple[TechniqueDef, ...] = (
    TechniqueDef(
        "owasp_llm01",
        "prompt_injection",
        "OWASP LLM01 Prompt injection",
        "Informational pointer to OWASP LLM Top 10 prompt injection. Not a vulnerability scan.",
        OWASP_LLM,
        "owasp",
        "owasp_genai",
        "LLM01",
        "prompt_interface",
    ),
    TechniqueDef(
        "atlas_aml_t0051",
        "prompt_injection",
        "MITRE ATLAS AML.T0051 LLM prompt injection",
        "Informational pointer to MITRE ATLAS AML.T0051. Not an exploit procedure.",
        ATLAS,
        "atlas",
        "mitre_atlas",
        "AML.T0051",
        "prompt_interface",
    ),
    TechniqueDef(
        "owasp_llm01_indirect",
        "prompt_injection",
        "OWASP LLM01 Indirect prompt injection",
        "Informational pointer: untrusted retrieved or tool-returned content may influence instructions. Not an exploit procedure.",
        OWASP_LLM,
        "owasp",
        "owasp_genai",
        "LLM01",
        "prompt_interface",
    ),
    TechniqueDef(
        "owasp_llm08",
        "tool_abuse",
        "OWASP LLM08 Excessive agency",
        "Informational pointer to OWASP LLM Top 10 excessive agency, relevant to unauthorized tool execution.",
        OWASP_LLM,
        "owasp",
        "owasp_genai",
        "LLM08",
        "agent_tools",
    ),
    TechniqueDef(
        "atlas_aml_t0048",
        "tool_abuse",
        "MITRE ATLAS AML.T0048 External harm via tool invocation",
        "Informational pointer to MITRE ATLAS AML.T0048. Not an exploit procedure.",
        ATLAS,
        "atlas",
        "mitre_atlas",
        "AML.T0048",
        "agent_tools",
    ),
    TechniqueDef(
        "atlas_aml_t0043",
        "memory_poisoning",
        "MITRE ATLAS AML.T0043 Craft adversarial data",
        "Informational pointer to MITRE ATLAS AML.T0043. Not an exploit procedure.",
        ATLAS,
        "atlas",
        "mitre_atlas",
        "AML.T0043",
        "memory_store",
    ),
    TechniqueDef(
        "owasp_llm06",
        "data_leakage",
        "OWASP LLM06 Sensitive information disclosure",
        "Informational pointer to OWASP LLM Top 10 sensitive information disclosure.",
        OWASP_LLM,
        "owasp",
        "owasp_genai",
        "LLM06",
        "model_output",
    ),
    TechniqueDef(
        "owasp_llm08_priv",
        "privilege_escalation",
        "OWASP LLM08 Excessive agency (privilege)",
        "Informational pointer: excessive agency as privilege overreach. Candidate test AUTH-01. Not an exploit procedure.",
        OWASP_LLM,
        "owasp",
        "owasp_genai",
        "LLM08",
        "agent_tools",
    ),
    TechniqueDef(
        "lab_cross_tenant",
        "cross_tenant",
        "Lab: cross-tenant tool or retrieval access",
        "Informational lab pointer: tenant isolation must be enforced outside the model. Not an exploit procedure.",
        OWASP_LLM,
        "lab",
        None,
        None,
        "tenant_boundary",
    ),
    TechniqueDef(
        "lab_mcp_poisoning",
        "mcp_poisoning",
        "Lab: MCP or tool-definition poisoning",
        "Informational lab pointer: untrusted tool catalogs can change what an agent believes it may call. Not an exploit procedure.",
        OWASP_LLM,
        "lab",
        None,
        None,
        "tool_definitions",
    ),
    TechniqueDef(
        "lab_oversight_bypass",
        "oversight_bypass",
        "Lab: human-oversight bypass",
        "Informational lab pointer: high-impact tools may complete without a required human gate. Not an exploit procedure.",
        OWASP_LLM,
        "lab",
        None,
        None,
        "human_oversight",
    ),
)

ADVISORIES: tuple[AdvisoryDef, ...] = (
    AdvisoryDef(
        "owasp-llm-top10",
        "OWASP GenAI LLM Top 10",
        "Curated index of OWASP GenAI LLM Top 10 topics. Informational catalog ingest, not a live crawl.",
        OWASP_LLM,
        "owasp",
        ("owasp_llm01", "owasp_llm01_indirect", "owasp_llm06", "owasp_llm08", "owasp_llm08_priv"),
    ),
    AdvisoryDef(
        "mitre-atlas-index",
        "MITRE ATLAS technique index",
        "Curated index of selected MITRE ATLAS techniques. Informational catalog ingest, not a live crawl.",
        ATLAS,
        "atlas",
        ("atlas_aml_t0051", "atlas_aml_t0048", "atlas_aml_t0043"),
    ),
    AdvisoryDef(
        "lab-unauthorized-tool",
        "Lab advisory: unauthorized tool invocation",
        "Synthetic labelled lab advisory for the order-support demo. Informational mapping of tool abuse to CTRL-002 and AUTH-01. Not a public incident.",
        ATLAS,
        "lab",
        ("owasp_llm08", "atlas_aml_t0048", "owasp_llm08_priv"),
    ),
    AdvisoryDef(
        "lab-m13-ops",
        "Lab advisory: AI operations threat set",
        "Synthetic labelled informational index for cross-tenant access, MCP/tool poisoning, oversight bypass, and indirect injection. Not a live feed.",
        OWASP_LLM,
        "lab",
        ("owasp_llm01_indirect", "lab_cross_tenant", "lab_mcp_poisoning", "lab_oversight_bypass"),
    ),
)

CTRL002_TECHNIQUES: tuple[str, ...] = ("owasp_llm08", "atlas_aml_t0048", "owasp_llm08_priv")

CTRL002_TESTS: tuple[TestSuggestionDef, ...] = (
    TestSuggestionDef(
        "owasp_llm08",
        AUTH_01,
        "Candidate: unauthorized high-impact tool use on the labelled demo. Does not execute a test.",
    ),
    TestSuggestionDef(
        "owasp_llm08",
        AUTH_02,
        "Candidate: authorized owner path remains in the CTRL-002 catalog. Does not execute a test.",
    ),
    TestSuggestionDef(
        "atlas_aml_t0048",
        AUTH_01,
        "Candidate: tool invocation harm on the labelled demo. Does not execute a test.",
    ),
    TestSuggestionDef(
        "owasp_llm08_priv",
        AUTH_01,
        "Candidate: privilege overreach via unauthorized tools. Does not execute a test.",
    ),
)


def threat_for(key: str) -> ThreatDef | None:
    return next((item for item in THREATS if item.key == key), None)


def technique_for(key: str) -> TechniqueDef | None:
    return next((item for item in TECHNIQUES if item.key == key), None)
