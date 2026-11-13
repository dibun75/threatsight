"""Official Cloudflare Radar response contracts. Unknown field names are schema drift."""

from __future__ import annotations

NORMALIZATIONS = {
    "PERCENTAGE",
    "MIN0_MAX",
    "MIN_MAX",
    "RAW_VALUES",
    "PERCENTAGE_CHANGE",
    "ROLLING_AVERAGE",
    "OVERLAPPED_PERCENTAGE",
    "RATIO",
}
LABEL = "Cloudflare-observed mitigated Layer 7 requests"
LIMITATIONS = [
    "Cloudflare-observed mitigated Layer 7 requests, not every attack on the Internet.",
    "Origin country is the client IP location and does not identify a person.",
    "Target country is the attacked zone billing location when Cloudflare supplies it.",
    "Values may be normalized shares rather than absolute global counts.",
    "A country measurement is not organization exposure.",
]


class RadarError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def parse_document(payload: bytes, *, kind: str) -> dict:
    if len(payload) > 1_000_000:
        raise RadarError("response_too_large")
    import json

    try:
        document = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise RadarError("malformed_json") from exc
    if not isinstance(document, dict) or document.get("success") is not True:
        raise RadarError("schema")
    result = document.get("result")
    if not isinstance(result, dict):
        raise RadarError("schema")
    meta = _meta(result)
    if kind == "origin":
        rows = _locations(result, code_field="originCountryAlpha2", name_field="originCountryName")
    elif kind == "target":
        rows = _locations(result, code_field="targetCountryAlpha2", name_field="targetCountryName")
    elif kind == "pairs":
        rows = _pairs(result)
    elif kind == "timeseries":
        rows = _series(result)
    elif kind == "mitigation":
        rows = _mitigation(result)
    else:
        raise RadarError("schema")
    return {"meta": meta, "rows": rows}


def _meta(result: dict) -> dict:
    meta = result.get("meta")
    if not isinstance(meta, dict):
        raise RadarError("schema")
    normalization = meta.get("normalization")
    if normalization not in NORMALIZATIONS:
        raise RadarError("schema")
    units = meta.get("units")
    if not isinstance(units, list) or not units or not all(isinstance(item, dict) and isinstance(item.get("name"), str) and isinstance(item.get("value"), str) for item in units):
        raise RadarError("schema")
    date_range = meta.get("dateRange")
    if not isinstance(date_range, list) or not date_range or not isinstance(date_range[0], dict):
        raise RadarError("schema")
    start = date_range[0].get("startTime")
    end = date_range[0].get("endTime")
    updated = meta.get("lastUpdated")
    if not all(isinstance(item, str) and item for item in (start, end, updated)):
        raise RadarError("schema")
    confidence, annotations = _confidence(meta)
    return {
        "normalization": normalization,
        "units": units[0]["value"][:64],
        "window_start": start,
        "window_end": end,
        "last_updated": updated,
        "confidence": confidence,
        "annotations": annotations,
    }


def _confidence(meta: dict) -> tuple[dict, list]:
    """Accept the official confidence object, including a null level.

    Cloudflare documents ``confidenceInfo.level`` as a number and currently
    returns null when it has not supplied a level. A missing object is stored
    as not supplied. Any other shape remains schema drift.
    """
    confidence = meta.get("confidenceInfo")
    if confidence is None:
        return {"level": None, "supplied": False}, []
    if not isinstance(confidence, dict):
        raise RadarError("schema")
    level = confidence.get("level")
    if level is not None and (isinstance(level, bool) or not isinstance(level, (int, float)) or level != level or abs(level) > 1_000_000):
        raise RadarError("schema")
    annotations = confidence.get("annotations", [])
    if annotations is None:
        annotations = []
    if not isinstance(annotations, list):
        raise RadarError("schema")
    safe = []
    for item in annotations[:20]:
        if not isinstance(item, dict):
            raise RadarError("schema")
        description = item.get("description", "")
        event_type = item.get("eventType", "")
        if not isinstance(description, str) or not isinstance(event_type, str) or _unsafe(description) or _unsafe(event_type):
            raise RadarError("schema")
        safe.append({"description": description[:180], "eventType": event_type[:40]})
    return {"level": level, "supplied": level is not None}, safe


def _locations(result: dict, *, code_field: str, name_field: str) -> list[dict]:
    rows = _top(result)
    parsed = []
    for item in rows:
        if "rank" not in item or "value" not in item or code_field not in item or name_field not in item:
            raise RadarError("schema")
        parsed.append(
            {
                "country": _code(item[code_field]),
                "name": _name(item[name_field]),
                "rank": _rank(item["rank"]),
                "value": _number(item["value"]),
            }
        )
    return parsed


def _pairs(result: dict) -> list[dict]:
    rows = _top(result)
    parsed = []
    for item in rows:
        for field in ("originCountryAlpha2", "originCountryName", "targetCountryAlpha2", "targetCountryName", "value"):
            if field not in item:
                raise RadarError("schema")
        parsed.append(
            {
                "origin": _code(item["originCountryAlpha2"]),
                "origin_name": _name(item["originCountryName"]),
                "target": _code(item["targetCountryAlpha2"]),
                "target_name": _name(item["targetCountryName"]),
                "value": _number(item["value"]),
            }
        )
    return parsed


def _series(result: dict) -> list[dict]:
    serie = result.get("serie_0")
    if not isinstance(serie, dict):
        raise RadarError("schema")
    stamps = serie.get("timestamps")
    values = serie.get("values")
    if not isinstance(stamps, list) or not isinstance(values, list) or len(stamps) != len(values) or len(stamps) > 500:
        raise RadarError("schema")
    return [{"observed_at": _stamp(stamp), "value": _number(value)} for stamp, value in zip(stamps, values, strict=True)]


def _mitigation(result: dict) -> list[dict]:
    summary = result.get("summary_0")
    if not isinstance(summary, dict) or len(summary) > 30:
        raise RadarError("schema")
    parsed = []
    for name, value in summary.items():
        if not isinstance(name, str) or _unsafe(name):
            raise RadarError("schema")
        parsed.append({"product": name[:80], "value": _number(value)})
    return parsed


def _top(result: dict) -> list[dict]:
    rows = result.get("top_0")
    if not isinstance(rows, list) or len(rows) > 100:
        raise RadarError("schema")
    if any(not isinstance(item, dict) for item in rows):
        raise RadarError("schema")
    return rows


def _code(value: object) -> str:
    if not isinstance(value, str) or len(value) != 2 or not value.isalpha() or not value.isupper():
        raise RadarError("country_code")
    return value


def _name(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or _unsafe(value) or len(value) > 80:
        raise RadarError("schema")
    return value


def _number(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise RadarError("schema")
    try:
        return float(value)
    except ValueError as exc:
        raise RadarError("schema") from exc


def _rank(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RadarError("schema")
    rank = int(value)
    if rank < 0:
        raise RadarError("schema")
    return rank


def _stamp(value: object) -> str:
    if not isinstance(value, str) or not value or _unsafe(value):
        raise RadarError("schema")
    return value


def _unsafe(value: str) -> bool:
    return any(character in value for character in "<>&")
