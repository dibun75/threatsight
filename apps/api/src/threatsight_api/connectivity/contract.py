from __future__ import annotations

SOURCE_KINDS = frozenset({"http_assessment", "gateway", "sdk", "otel"})


class ConnectivityIngestError(ValueError):
    pass
