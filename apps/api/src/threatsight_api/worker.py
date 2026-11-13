from __future__ import annotations

import signal
import time

from threatsight_api.config import get_settings
from threatsight_api.connectors.execution import claim_job, fail_job
from threatsight_api.persistence.session import SessionLocal, configure_engine

_running = True


def _stop(*_args) -> None:
    global _running
    _running = False


def run_once() -> bool:
    settings = get_settings()
    if settings.kill_switch:
        return False
    with SessionLocal() as db:
        job = claim_job(db, settings, owner="control-plane-worker", local_only=True)
        if job is None:
            db.commit()
            return False
        db.commit()
        db.refresh(job)
        if get_settings().kill_switch:
            fail_job(db, job, "control-plane-worker", "kill_switch", "Execution disabled before dispatch", retryable=True)
        else:
            fail_job(
                db, job, "control-plane-worker", "unsupported_connector",
                "No in-process connector implementation is registered for this connector key",
                retryable=False,
            )
        db.commit()
        return True


def main() -> None:
    configure_engine()
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    while _running:
        if not run_once():
            time.sleep(get_settings().worker_poll_seconds)


if __name__ == "__main__":
    main()
