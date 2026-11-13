"""Outbound public-intelligence worker. It does not run customer connectors."""

from __future__ import annotations

import os
import signal
import sys
import time
import uuid

from sqlalchemy import text

from threatsight_api.config import get_settings
from threatsight_api.intel.collect import SOURCES, collect_source
from threatsight_api.multisource.collect import collect_due as collect_multisource_due
from threatsight_api.telemetry.worker import maybe_collect
from threatsight_api.observatory.greynoise_worker import (
    process_pending as process_greynoise_pending,
)
from threatsight_api.observatory.worker import (
    maybe_collect as maybe_collect_observatory,
)
from threatsight_api.observatory.threatfox_worker import (
    maybe_collect as maybe_collect_threatfox,
)
from threatsight_api.observatory.abusech_worker import maybe_collect as maybe_collect_abusech
from threatsight_api.persistence.session import SessionLocal, configure_engine

_running = True


def _stop(*_args) -> None:
    global _running
    _running = False


def _beat() -> None:
    path = "/tmp/intel-alive"
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("ok")


def run_due(owner: str | None = None) -> list[dict]:
    settings = get_settings()
    if settings.kill_switch or os.environ.get(
        "THREATSIGHT_INTEL_KILL_SWITCH", ""
    ).lower() in {"1", "true", "yes"}:
        return []
    owner = owner or f"intel-{uuid.uuid4().hex[:8]}"
    results = []
    with SessionLocal() as db:
        allowed = list(SOURCES)
        only = os.environ.get("THREATSIGHT_INTEL_ONLY", "").strip()
        if only:
            allowed = [key for key in only.split(",") if key in SOURCES]
        rows = db.execute(
            text(
                """
                SELECT source_key FROM landscape_schedules
                 WHERE enabled AND NOT kill_switch AND next_attempt_at <= now()
                   AND source_key = ANY(:keys)
                 ORDER BY source_key
                """
            ),
            {"keys": allowed},
        ).all()
        for row in rows:
            if not _running:
                break
            result = collect_source(db, row.source_key, owner=owner)
            db.commit()
            results.append({"source": row.source_key, **result})
        try:
            radar = maybe_collect(db, running=_running)
            db.commit()
            results.append({"source": "cloudflare_radar", **radar})
        except Exception:
            db.rollback()
            results.append(
                {"source": "cloudflare_radar", "state": "failed_no_snapshot"}
            )
        try:
            observatory = maybe_collect_observatory(db)
            db.commit()
            results.append({"source": "dshield", **observatory})
        except Exception:
            db.rollback()
            results.append({"source": "dshield", "state": "failed_no_snapshot"})
        try:
            threatfox = maybe_collect_threatfox(db)
            db.commit()
            results.append({"source": "threatfox", **threatfox})
        except Exception:
            db.rollback()
            results.append({"source": "threatfox", "state": "failed_no_snapshot"})
        for feed in ("feodo", "urlhaus"):
            try:
                collected = maybe_collect_abusech(db, feed)
                db.commit()
                results.append({"source": feed, **collected})
            except Exception:
                db.rollback()
                results.append({"source": feed, "state": "failed_no_snapshot"})
        try:
            greynoise = process_greynoise_pending(db)
            db.commit()
            results.append({"source": "greynoise", **greynoise})
        except Exception:
            db.rollback()
            results.append({"source": "greynoise", "state": "failed"})
        try:
            for item in collect_multisource_due(db):
                results.append(item)
            db.commit()
        except Exception:
            db.rollback()
            results.append({"source": "multisource", "state": "failed"})
    return results


def main() -> None:
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    configure_engine()
    once = "--once" in sys.argv
    while _running:
        _beat()
        run_due()
        if once:
            break
        time.sleep(30)


if __name__ == "__main__":
    main()
