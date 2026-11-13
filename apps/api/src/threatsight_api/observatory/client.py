"""Bounded unauthenticated client for explicitly allowlisted DShield static feeds."""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

from threatsight_api.observatory.contract import ObservatoryError

ENDPOINTS = {
    "top_ips": ("feeds.dshield.org", "/feeds/topips.txt"),
    "top_ports": ("feeds.dshield.org", "/feeds/topports.txt"),
    "threat_intel": ("isc.sans.edu", "/feeds/threatintel.txt"),
}
# threatintel.txt passed 11 MB in Nov 2026; keep a bound with headroom.
MAX_RESPONSE = 32_000_000


def fetch_dataset(dataset: str, *, opener=None) -> bytes:
    if dataset not in ENDPOINTS:
        raise ObservatoryError("request_rejected")
    host, path = ENDPOINTS[dataset]
    url = f"https://{host}{path}"
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != host or parsed.path != path:
        raise ObservatoryError("request_rejected")
    request = urllib.request.Request(url, headers={"Accept": "text/plain", "User-Agent": "ThreatSight/1.0 (+https://threatsight.io)"}, method="GET")

    class _Guard(urllib.request.HTTPRedirectHandler):
        max_redirections = 2

        def redirect_request(self, req, fp, code, msg, headers, newurl):
            target = urllib.parse.urlparse(newurl)
            if target.scheme != "https" or target.hostname != host or target.path != path:
                raise ObservatoryError("redirect_rejected")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    active = opener or urllib.request.build_opener(_Guard)
    try:
        response = active.open(request, timeout=30)
    except ObservatoryError:
        raise
    except urllib.error.HTTPError as exc:
        raise ObservatoryError("rate_limited" if exc.code == 429 else "http_status") from exc
    except TimeoutError as exc:
        raise ObservatoryError("timeout") from exc
    except Exception as exc:
        raise ObservatoryError("request_failed") from exc
    final = urllib.parse.urlparse(response.geturl())
    if final.scheme != "https" or final.hostname != host or final.path != path:
        raise ObservatoryError("redirect_rejected")
    payload = response.read(MAX_RESPONSE + 1)
    if len(payload) > MAX_RESPONSE:
        raise ObservatoryError("response_too_large")
    return payload
