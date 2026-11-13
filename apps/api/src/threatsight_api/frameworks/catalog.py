from __future__ import annotations

from dataclasses import dataclass

CATALOG_VERSION = "m6-2026-08"

EU_AI_ACT = "https://eur-lex.europa.eu/eli/reg/2024/1689/oj"
GDPR = "https://eur-lex.europa.eu/eli/reg/2016/679/oj"
NIST_RMF = "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf"
ISO_42001 = "https://www.iso.org/standard/81230.html"
OWASP_LLM = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
ATLAS = "https://atlas.mitre.org/"


@dataclass(frozen=True)
class FrameworkMeta:
    key: str
    title: str
    locator: str


@dataclass(frozen=True)
class CatalogItem:
    framework_key: str
    reference_code: str
    title: str
    statement: str
    locator: str
    source_kind: str


FRAMEWORKS: tuple[FrameworkMeta, ...] = (
    FrameworkMeta("eu_ai_act", "EU AI Act", EU_AI_ACT),
    FrameworkMeta("gdpr", "GDPR", GDPR),
    FrameworkMeta("nist_ai_rmf", "NIST AI RMF", NIST_RMF),
    FrameworkMeta("iso_42001", "ISO/IEC 42001", ISO_42001),
    FrameworkMeta("owasp_genai", "OWASP GenAI / LLM Top 10", OWASP_LLM),
    FrameworkMeta("mitre_atlas", "MITRE ATLAS", ATLAS),
)

CATALOG_ITEMS: tuple[CatalogItem, ...] = (
    CatalogItem(
        "eu_ai_act",
        "Art-9",
        "Risk management system",
        "Informational topic: a risk-management system for high-risk AI. Not a legal extraction of Article 9.",
        EU_AI_ACT,
        "official_locator",
    ),
    CatalogItem(
        "eu_ai_act",
        "Art-14",
        "Human oversight",
        "Informational topic: human oversight of high-risk AI systems. Not a legal extraction of Article 14.",
        EU_AI_ACT,
        "official_locator",
    ),
    CatalogItem(
        "eu_ai_act",
        "Art-15",
        "Accuracy, robustness and cybersecurity",
        "Informational topic: accuracy, robustness, and cybersecurity of high-risk AI. Not a legal extraction of Article 15.",
        EU_AI_ACT,
        "official_locator",
    ),
    CatalogItem(
        "gdpr",
        "Art-32",
        "Security of processing",
        "Informational topic: security of personal-data processing. Not a legal extraction of Article 32.",
        GDPR,
        "official_locator",
    ),
    CatalogItem(
        "gdpr",
        "Art-25",
        "Data protection by design and by default",
        "Informational topic: data protection by design and by default. Not a legal extraction of Article 25.",
        GDPR,
        "official_locator",
    ),
    CatalogItem(
        "gdpr",
        "Art-5.1.f",
        "Integrity and confidentiality",
        "Informational topic: integrity and confidentiality of personal data. Not a legal extraction of Article 5.",
        GDPR,
        "official_locator",
    ),
    CatalogItem(
        "nist_ai_rmf",
        "MAP-1.1",
        "Map AI systems and intended uses",
        "Informational topic: mapping AI systems and intended purposes. Curated pointer into NIST AI RMF 1.0.",
        NIST_RMF,
        "official_locator",
    ),
    CatalogItem(
        "nist_ai_rmf",
        "GOVERN-1.1",
        "Legal and regulatory requirements are understood",
        "Informational topic: understanding applicable legal and regulatory requirements. Curated pointer, not a compliance result.",
        NIST_RMF,
        "official_locator",
    ),
    CatalogItem(
        "nist_ai_rmf",
        "MEASURE-2.3",
        "AI system performance and trustworthiness are measured",
        "Informational topic: measuring AI system performance and trustworthiness characteristics.",
        NIST_RMF,
        "official_locator",
    ),
    CatalogItem(
        "nist_ai_rmf",
        "MANAGE-1.1",
        "AI risks are prioritized and managed",
        "Informational topic: prioritizing and managing mapped AI risks.",
        NIST_RMF,
        "official_locator",
    ),
    CatalogItem(
        "iso_42001",
        "6.1",
        "Actions to address risks and opportunities",
        "Informational index into ISO/IEC 42001 clause 6.1. The standard text is not reproduced.",
        ISO_42001,
        "standards_index",
    ),
    CatalogItem(
        "iso_42001",
        "5.3",
        "Organizational roles, responsibilities and authorities",
        "Informational index into ISO/IEC 42001 clause 5.3. The standard text is not reproduced.",
        ISO_42001,
        "standards_index",
    ),
    CatalogItem(
        "iso_42001",
        "8.2",
        "AI risk assessment",
        "Informational index into ISO/IEC 42001 clause 8.2. The standard text is not reproduced.",
        ISO_42001,
        "standards_index",
    ),
    CatalogItem(
        "owasp_genai",
        "LLM01",
        "Prompt injection",
        "Informational pointer to OWASP LLM Top 10 prompt injection. Not a vulnerability scan.",
        OWASP_LLM,
        "guidance",
    ),
    CatalogItem(
        "owasp_genai",
        "LLM06",
        "Sensitive information disclosure",
        "Informational pointer to OWASP LLM Top 10 sensitive information disclosure.",
        OWASP_LLM,
        "guidance",
    ),
    CatalogItem(
        "owasp_genai",
        "LLM08",
        "Excessive agency",
        "Informational pointer to OWASP LLM Top 10 excessive agency, relevant to tool authorization.",
        OWASP_LLM,
        "guidance",
    ),
    CatalogItem(
        "mitre_atlas",
        "AML.T0048",
        "External harm via tool invocation",
        "Informational pointer to MITRE ATLAS technique AML.T0048. Not an exploit procedure.",
        ATLAS,
        "guidance",
    ),
    CatalogItem(
        "mitre_atlas",
        "AML.T0051",
        "LLM prompt injection",
        "Informational pointer to MITRE ATLAS technique AML.T0051.",
        ATLAS,
        "guidance",
    ),
    CatalogItem(
        "mitre_atlas",
        "AML.T0043",
        "Craft adversarial data",
        "Informational pointer to MITRE ATLAS technique AML.T0043.",
        ATLAS,
        "guidance",
    ),
)

CTRL002_SUGGESTIONS: tuple[tuple[str, str], ...] = (
    ("owasp_genai", "LLM08"),
    ("mitre_atlas", "AML.T0048"),
    ("eu_ai_act", "Art-9"),
    ("eu_ai_act", "Art-15"),
    ("nist_ai_rmf", "GOVERN-1.1"),
)


def meta_for(key: str) -> FrameworkMeta | None:
    return next((item for item in FRAMEWORKS if item.key == key), None)
