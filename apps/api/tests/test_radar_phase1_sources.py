from pathlib import Path

import pytest

from threatsight_api.radar.fetch import SourceFetchError, _validate_url, source_url
from threatsight_api.radar.parsers import (
    parse_authority_rss,
    parse_cert_se_atom,
    parse_enisa_euvd,
)

FIXTURES = Path(__file__).parent / "fixtures" / "radar"


def test_cert_se_atom_is_plain_text_with_explicit_geography() -> None:
    event = parse_cert_se_atom((FIXTURES / "cert-se-atom.xml").read_bytes())[0]
    assert event.event_type == "advisory"
    assert event.authority_jurisdictions == ["SE"]
    assert event.target_countries == []
    assert event.cves == ["CVE-2026-12345"]
    assert "<script>" not in event.summary
    assert len(event.source_payload_hash) == 64
    assert event.parser_version == "phase1-v1"


def test_event_hash_is_stable_when_an_unrelated_feed_entry_is_added() -> None:
    payload = (FIXTURES / "cert-se-atom.xml").read_bytes()
    original = parse_cert_se_atom(payload)[0]
    expanded = payload.replace(
        b"</feed>",
        b"<entry><id>other</id><title>Other item</title>"
        b"<summary>Unrelated</summary><link href=\"https://www.cert.se/other/\" />"
        b"</entry></feed>",
    )
    assert parse_cert_se_atom(expanded)[0].source_payload_hash == original.source_payload_hash


@pytest.mark.parametrize(
    ("fixture", "authority", "jurisdiction", "language"),
    [
        ("ncsc-fi-rss.xml", "NCSC-FI", "FI", "fi"),
        ("cert-eu-rss.xml", "CERT-EU", "EU", "en"),
    ],
)
def test_authority_rss_preserves_provenance(
    fixture: str, authority: str, jurisdiction: str, language: str
) -> None:
    event = parse_authority_rss(
        (FIXTURES / fixture).read_bytes(),
        authority=authority,
        jurisdiction=jurisdiction,
        language=language,
    )[0]
    assert event.authority_jurisdictions == [jurisdiction]
    assert event.provenance["authority"] == authority
    assert event.target_countries == []
    assert event.event_type == "advisory"


def test_euvd_parser_stores_bounded_metadata() -> None:
    event = parse_enisa_euvd((FIXTURES / "enisa-euvd.json").read_bytes())[0]
    assert event.external_id == "EUVD-2026-12345"
    assert event.event_type == "vulnerability"
    assert event.authority_jurisdictions == ["EU"]
    assert event.vendors == ["Example Vendor"]
    assert event.products == ["Secure Product"]
    assert event.cves == ["CVE-2026-12345"]


def test_euvd_url_parameters_are_bounded() -> None:
    url = source_url("enisa-euvd", query={"page": 0, "size": 100})
    assert url.startswith("https://euvdservices.enisa.europa.eu/api/search?")
    with pytest.raises(SourceFetchError):
        source_url("enisa-euvd", query={"page": 0, "size": 101})
    with pytest.raises(SourceFetchError):
        source_url("enisa-euvd", query={"page": 0, "size": 10, "redirect": "https://example.com"})


def test_redirect_destination_must_match_the_exact_requested_url() -> None:
    requested = source_url("cert-se-atom")
    _validate_url("cert-se-atom", requested, requested)
    with pytest.raises(SourceFetchError):
        _validate_url("cert-se-atom", "https://example.com/feed/atom.xml", requested)
    with pytest.raises(SourceFetchError):
        _validate_url("cert-se-atom", f"{requested}?redirected=1", requested)


def test_xml_parser_rejects_entities() -> None:
    unsafe = b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><rss><item>&e;</item></rss>'
    with pytest.raises(ValueError, match="unsafe"):
        parse_authority_rss(unsafe, authority="test", jurisdiction="SE", language="en")
