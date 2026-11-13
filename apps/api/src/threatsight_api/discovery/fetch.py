from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from threatsight_api.config import Settings
from threatsight_api.discovery.pages import PAGES
from threatsight_api.discovery.safety import DiscoverySafetyError, assert_url_allowed, normalize_url

ALLOWED_TYPES = ("text/html", "application/xhtml+xml", "text/plain")
MAX_REDIRECTS = 2


@dataclass
class FetchedPage:
    url: str
    final_url: str
    status: int
    content_type: str
    body: bytes
    text: str


class DiscoveryFetchError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502) -> None:
        super().__init__(message)
        self.status_code = status_code


class _BoundedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings
        self.hops = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if self.hops >= MAX_REDIRECTS:
            raise DiscoverySafetyError("Too many redirects", 400)
        self.hops += 1
        assert_url_allowed(newurl, self.settings)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_page(url: str, settings: Settings) -> FetchedPage:
    assert_url_allowed(url, settings)
    if settings.discovery_adapter == "inprocess":
        return _fetch_inprocess(url)
    if settings.discovery_adapter == "http":
        return _fetch_http(url, settings)
    raise DiscoveryFetchError(f"Unknown discovery adapter: {settings.discovery_adapter}", 400)


def _fetch_inprocess(url: str) -> FetchedPage:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    body_text = PAGES.get(path)
    if body_text is None:
        raise DiscoveryFetchError(f"In-process page not found: {path}", 404)
    data = body_text.encode()
    content_type = "text/plain; charset=utf-8" if path == "/robots.txt" else "text/html; charset=utf-8"
    return FetchedPage(
        url=normalize_url(url),
        final_url=normalize_url(url),
        status=200,
        content_type=content_type,
        body=data,
        text=body_text,
    )


def _fetch_http(url: str, settings: Settings) -> FetchedPage:
    opener = urllib.request.build_opener(
        _BoundedRedirectHandler(settings),
        urllib.request.HTTPSHandler(),
        urllib.request.HTTPHandler(),
    )
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "ThreatSight-Discovery/2.0", "Accept": "text/html, text/plain"},
    )
    try:
        with opener.open(request, timeout=8) as response:
            status = getattr(response, "status", 200)
            content_type = (response.headers.get("Content-Type") or "text/html").split(";")[0].strip().lower()
            if content_type not in ALLOWED_TYPES:
                raise DiscoverySafetyError("Content type is not allowed", 400)
            chunk = response.read(settings.discovery_max_bytes + 1)
            if len(chunk) > settings.discovery_max_bytes:
                raise DiscoverySafetyError("Fetched document exceeds size cap", 413)
            final_url = normalize_url(response.geturl() or url)
            assert_url_allowed(final_url, settings)
            text = chunk.decode("utf-8", errors="replace")
            return FetchedPage(
                url=normalize_url(url),
                final_url=final_url,
                status=int(status),
                content_type=content_type,
                body=chunk,
                text=text,
            )
    except DiscoverySafetyError:
        raise
    except urllib.error.HTTPError as exc:
        raise DiscoveryFetchError(f"Fetch failed with HTTP {exc.code}", 502) from exc
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise DiscoveryFetchError("Discovery fetch failed") from exc


def join_same_origin(base: str, href: str) -> str | None:
    if not href or href.startswith(("#", "mailto:", "javascript:")):
        return None
    absolute = urljoin(base, href)
    parsed = urlparse(absolute)
    base_parsed = urlparse(base)
    if parsed.scheme != base_parsed.scheme or parsed.netloc.lower() != base_parsed.netloc.lower():
        return None
    return normalize_url(absolute)
