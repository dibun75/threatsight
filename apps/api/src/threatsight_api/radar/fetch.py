from __future__ import annotations

import urllib.parse
import urllib.request

SOURCE_URLS = {
    "cisa-kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "nsm-rss": "https://nsm.no/rss/sarbarhetsvarsler-fra-nsm/",
    "first-epss": "https://api.first.org/data/v1/epss",
    "cert-se-atom": "https://www.cert.se/feed/atom.xml",
    "ncsc-fi-rss": "https://www.kyberturvallisuuskeskus.fi/feed/rss/fi/400",
    "enisa-euvd": "https://euvdservices.enisa.europa.eu/api/search",
    "cert-eu-rss": "https://cert.europa.eu/publications/security-advisories-rss",
}
MAX_SOURCE_BYTES = 8 * 1024 * 1024
ALLOWED_CONTENT_TYPES = {
    "application/json",
    "application/xml",
    "application/rss+xml",
    "application/atom+xml",
    "text/xml",
}


class SourceFetchError(RuntimeError):
    pass


def source_url(
    source_key: str,
    cves: list[str] | None = None,
    query: dict[str, str | int] | None = None,
) -> str:
    if source_key not in SOURCE_URLS:
        raise SourceFetchError("Unknown threat source")
    base = SOURCE_URLS[source_key]
    if source_key == "first-epss":
        values = sorted({item.upper() for item in (cves or []) if item.upper().startswith("CVE-")})
        if not values:
            raise SourceFetchError("EPSS sync requires at least one CVE")
        if len(values) > 100:
            raise SourceFetchError("EPSS batch exceeds 100 CVEs")
        return f"{base}?{urllib.parse.urlencode({'cve': ','.join(values)})}"
    if source_key == "enisa-euvd":
        allowed = {"fromUpdatedDate", "toUpdatedDate", "page", "size"}
        supplied = query or {}
        if not supplied or not set(supplied).issubset(allowed):
            raise SourceFetchError("EUVD sync requires bounded page parameters")
        size = int(supplied.get("size", 0))
        page = int(supplied.get("page", -1))
        if size < 1 or size > 100 or page < 0 or page > 50:
            raise SourceFetchError("EUVD page is outside the allowed bounds")
        return f"{base}?{urllib.parse.urlencode(supplied)}"
    return base


def _validate_url(source_key: str, value: str, requested_url: str) -> None:
    allowed = urllib.parse.urlparse(requested_url)
    actual = urllib.parse.urlparse(value)
    if (
        actual.scheme != "https"
        or actual.hostname != allowed.hostname
        or actual.path != allowed.path
        or actual.query != allowed.query
        or actual.params != allowed.params
    ):
        raise SourceFetchError("Threat-source redirect left the allow-listed endpoint")


class _ExactRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, source_key: str, requested_url: str) -> None:
        super().__init__()
        self.source_key = source_key
        self.requested_url = requested_url

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_url(self.source_key, newurl, self.requested_url)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_source(
    source_key: str,
    cves: list[str] | None = None,
    query: dict[str, str | int] | None = None,
) -> bytes:
    url = source_url(source_key, cves, query)
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json, application/rss+xml, application/xml, text/xml",
            "User-Agent": "ThreatSight-Radar/1.0",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(_ExactRedirectHandler(source_key, url))
    try:
        with opener.open(request, timeout=20) as response:
            _validate_url(source_key, response.geturl(), url)
            content_type = response.headers.get_content_type()
            if content_type not in ALLOWED_CONTENT_TYPES:
                raise SourceFetchError(f"Unexpected source content type: {content_type}")
            length = response.headers.get("Content-Length")
            if length and int(length) > MAX_SOURCE_BYTES:
                raise SourceFetchError("Threat-source response is too large")
            payload = response.read(MAX_SOURCE_BYTES + 1)
    except SourceFetchError:
        raise
    except Exception as exc:
        raise SourceFetchError(f"Threat-source request failed: {type(exc).__name__}") from exc
    if len(payload) > MAX_SOURCE_BYTES:
        raise SourceFetchError("Threat-source response is too large")
    return payload
