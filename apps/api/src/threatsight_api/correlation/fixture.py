"""Synthetic correlation events. These are not customer intelligence."""

from __future__ import annotations


def reference_events() -> list[dict]:
    return [
        _event("exact", "CVE-2024-1001", vendors=["acme"], products=["widget"], cpes=["cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*"], ranges=["=1.2.3"], authority=["US"]),
        _event("range", "CVE-2024-1002", vendors=["acme"], products=["widget"], ranges=[">=1.2.0,<1.3.0"], freshness="stale", epss=0.2),
        _event("alias", "CVE-2024-1003", vendors=["acme"], products=["widget"], ranges=[">=1.2.0,<1.3.0"]),
        _event("firmware", "CVE-2024-2001", vendors=["meraki"], products=["meraki"], ranges=[">=29.0,<30.0"]),
        _event("junos", "CVE-2024-3001", vendors=["juniper"], products=["junos"], ranges=[">=23.0,<24.0"]),
        _event("conflict-in", "CVE-2024-4001", vendors=["acme"], products=["widget"], ranges=[">=1.2.3,<1.2.4"], cluster="cluster-conflict"),
        _event("conflict-out", "CVE-2024-4001", vendors=["acme"], products=["widget"], ranges=[">=9.0.0,<9.1.0"], cluster="cluster-conflict"),
        _event("dup-a", "CVE-2024-5001", vendors=["acme"], products=["widget"], cpes=["cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*"], ranges=["=1.2.3"], cluster="cluster-dup"),
        _event("dup-b", "CVE-2024-5001", vendors=["acme"], products=["widget"], cpes=["cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*"], ranges=["=1.2.3"], cluster="cluster-dup"),
        _event("outside", "CVE-2024-6001", vendors=["acme"], products=["widget"], ranges=[">=9.0.0,<9.1.0"]),
        _event("cloud", "CVE-2024-7001", cloud_service="synthetic.web", cloud_scope="resource"),
        _event("provider", "CVE-2024-7002", vendors=["microsoft"], products=["azure"]),
        _event("purl", "CVE-2024-8001", purls=["pkg:generic/acme/helper@2.0.0"], ranges=[">=2.0.0,<2.1.0"], vendors=["acme"], products=["helper"]),
        _event("kev", "CVE-2024-1001", vendors=["acme"], products=["widget"], cpes=["cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*"], ranges=["=1.2.3"], kev=True),
    ]


def reference_aliases() -> list[dict]:
    return [{"alias_vendor": "acme", "alias_product": "synth-widget", "vendor": "acme", "product": "widget", "version": "1"}]


def _event(name, cve, **extra) -> dict:
    return {
        "event_id": name,
        "cluster_key": extra.get("cluster"),
        "cves": [cve],
        "cpes": extra.get("cpes") or [],
        "vendors": extra.get("vendors") or [],
        "products": extra.get("products") or [],
        "version_ranges": extra.get("ranges") or [],
        "purls": extra.get("purls") or [],
        "cloud_service": extra.get("cloud_service") or "",
        "cloud_scope": extra.get("cloud_scope") or "",
        "exploitation_status": "known_exploited" if extra.get("kev") else "unknown",
        "epss_score": extra.get("epss"),
        "epss_date": "2026-10-01" if extra.get("epss") is not None else None,
        "freshness": extra.get("freshness") or "fresh",
        "authority_jurisdictions": extra.get("authority") or [],
        "target_countries": ["SE"] if extra.get("authority") else [],
        "victim_countries": [],
        "infrastructure_countries": [],
        "prevalence_countries": [],
        "source_key": "synthetic-correlation",
        "provenance": {"parser": "p2-13.v1"},
    }
