from __future__ import annotations

import gzip
import hashlib
import io
import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request as urlrequest

class FetchError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _public_host(hostname: str) -> None:
    try:
        infos = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FetchError("dns_failed") from exc
    if not infos:
        raise FetchError("dns_failed")
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if not address.is_global:
            raise FetchError("private_address")


def fetch_https(
    url: str,
    *,
    hostname: str,
    limit: int,
    timeout: int = 30,
    etag: str | None = None,
    accept: str = "*/*",
) -> tuple[int, dict[str, str], bytes]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != hostname:
        raise FetchError("host_rejected")
    _public_host(hostname)
    headers = {"User-Agent": "ThreatSight-Intel/1.0", "Accept": accept}
    if etag:
        headers["If-None-Match"] = etag
    request = urlrequest.Request(url, headers=headers, method="GET")

    class _Guard(urlrequest.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if not urllib.parse.urlparse(newurl).netloc:
                newurl = urllib.parse.urljoin(req.full_url, newurl)
            target = urllib.parse.urlparse(newurl)
            if target.scheme != "https" or target.hostname != hostname:
                raise FetchError("redirect_rejected")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urlrequest.build_opener(_Guard)
    try:
        response = opener.open(request, timeout=timeout)
    except FetchError:
        raise
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return 304, {"etag": etag or ""}, b""
        if exc.code == 429:
            raise FetchError("rate_limited") from exc
        raise FetchError("http_status") from exc
    except Exception as exc:
        raise FetchError("request_failed") from exc
    final = urllib.parse.urlparse(response.geturl())
    if final.scheme != "https" or final.hostname != hostname:
        raise FetchError("redirect_rejected")
    payload = response.read(limit + 1)
    if len(payload) > limit:
        raise FetchError("response_too_large")
    meta = {
        "etag": response.headers.get("ETag", ""),
        "last_modified": response.headers.get("Last-Modified", ""),
        "content_type": response.headers.get_content_type(),
    }
    return response.status, meta, payload


def gunzip_bounded(payload: bytes, limit: int) -> bytes:
    if not payload.startswith(b"\x1f\x8b"):
        raise FetchError("unexpected_content")
    output = io.BytesIO()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as handle:
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                output.write(chunk)
                if output.tell() > limit:
                    raise FetchError("decompression_too_large")
    except FetchError:
        raise
    except Exception as exc:
        raise FetchError("decompression_failed") from exc
    return output.getvalue()


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
