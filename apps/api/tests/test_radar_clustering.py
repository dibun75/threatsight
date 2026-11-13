import uuid
from types import SimpleNamespace

from threatsight_api.radar.clustering import _desired_clusters


def _event(title: str, cves: list[str], source: str):
    return SimpleNamespace(
        id=uuid.uuid4(),
        title=title,
        cves=cves,
        source_id=uuid.UUID(source),
    )


def test_exact_duplicate_and_related_clusters_are_distinguishable() -> None:
    first = _event(
        "Critical VPN issue",
        ["CVE-2026-12345"],
        "00000000-0000-4000-8000-000000000001",
    )
    duplicate = _event(
        "Critical VPN issue!",
        ["CVE-2026-12345"],
        "00000000-0000-4000-8000-000000000002",
    )
    clusters = _desired_clusters([first, duplicate])
    assert {item["relationship_type"] for item in clusters.values()} == {
        "exact_duplicate",
        "related",
    }


def test_related_cluster_requires_cross_source_shared_cve() -> None:
    first = _event(
        "First advisory",
        ["CVE-2026-12345"],
        "00000000-0000-4000-8000-000000000001",
    )
    second = _event(
        "Second advisory",
        ["CVE-2026-99999"],
        "00000000-0000-4000-8000-000000000002",
    )
    same_source = _event(
        "Third advisory",
        ["CVE-2026-12345"],
        "00000000-0000-4000-8000-000000000001",
    )
    assert _desired_clusters([first, second]) == {}
    assert _desired_clusters([first, same_source]) == {}


def test_clustering_is_order_independent() -> None:
    events = [
        _event(
            "First advisory",
            ["CVE-2026-12345"],
            "00000000-0000-4000-8000-000000000001",
        ),
        _event(
            "Different report",
            ["CVE-2026-12345"],
            "00000000-0000-4000-8000-000000000002",
        ),
    ]
    assert set(_desired_clusters(events)) == set(_desired_clusters(list(reversed(events))))
