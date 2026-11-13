from threatsight_api.services.copy import counted


def build_executive_summary(dashboard: dict) -> dict:
    systems = int(dashboard.get("systems", {}).get("count", 0))
    controls = int(dashboard.get("controls", {}).get("count", 0))
    with_verdict = int(dashboard.get("controls", {}).get("with_technical_verdict", 0))
    ops_gaps = dashboard.get("operations", {}).get("control_coverage", {}).get("gaps")
    gaps = int(
        ops_gaps
        if ops_gaps is not None
        else dashboard.get("controls", {}).get("by_assurance_status", {}).get("GAP_DETECTED", 0)
    )
    open_high = int(dashboard.get("findings", {}).get("high_or_critical_open", 0))
    open_findings = int(dashboard.get("findings", {}).get("open", 0))
    freshness = dashboard.get("evidence_freshness") or {}
    window = int(freshness.get("window_days", 30))
    stale = int(freshness.get("stale_controls", 0))
    untested = int(freshness.get("untested_controls", 0))
    mapped_frameworks = int(dashboard.get("frameworks", {}).get("mapped_items", 0))
    framework_items = int(dashboard.get("frameworks", {}).get("item_count", 0))
    sentences = [
        f"{counted(systems, 'AI system')} in inventory.",
        f"{with_verdict} of {counted(controls, 'control')} {('has' if with_verdict == 1 else 'have')} a technical verdict.",
        f"{counted(gaps, 'control')} in GAP_DETECTED without a PASS retest.",
        f"{counted(open_high, 'open high or critical finding')}; {counted(open_findings, 'open finding')} in total.",
        f"{counted(stale, 'control', verb_one='has', verb_many='have')} STALE evidence against a {window}-day window; {untested} remain UNTESTED.",
        f"{mapped_frameworks} of {framework_items} curated framework items are mapped. Catalogs are incomplete and mappings are informational.",
        "Dashboard counts show data origin, evidence source, generated-by, and last-updated from persisted records. Synthetic demo inventory is labelled.",
        "This is technical assurance, not a legal compliance result.",
    ]
    return {
        "llm_authored": False,
        "narrative_authority": "deterministic_counts",
        "legal_compliance_claim": False,
        "sentences": sentences,
        "links": [
            {"href": "/showcase", "label": "Guided showcase"},
            {"href": "/controls", "label": "Controls"},
            {"href": "/evidence", "label": "Evidence"},
            {"href": "/exports", "label": "Control matrix export"},
        ],
    }
