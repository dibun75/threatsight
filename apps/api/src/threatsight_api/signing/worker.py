"""Dedicated evidence-signing worker loop. Private key is file-mounted only here."""

from __future__ import annotations

import os
import socket
import time
from pathlib import Path

from sqlalchemy.orm import Session

from sqlalchemy import select

from threatsight_api.persistence.models import Workspace
from threatsight_api.persistence.session import get_engine
from threatsight_api.persistence.signing_models import EvidenceSigningKey
from threatsight_api.signing import DEFAULT_DEPLOYMENT_ID
from threatsight_api.signing.provider import FileEd25519Provider
from threatsight_api.signing.service import (
    activate_key,
    claim_pending_request,
    ensure_policy,
    fail_request,
    process_request,
    register_public_key,
)


def _alive_path() -> Path:
    return Path(os.environ.get("THREATSIGHT_SIGNER_ALIVE_FILE", "/tmp/evidence-signer-alive"))


def _touch_alive() -> None:
    path = _alive_path()
    path.write_text(str(time.time()), encoding="utf-8")


def readiness() -> tuple[bool, str]:
    key_path = Path(os.environ.get("THREATSIGHT_EVIDENCE_SIGNING_KEY_FILE", "/run/secrets/evidence_signing_key"))
    key_id = os.environ.get("THREATSIGHT_EVIDENCE_SIGNING_KEY_ID", "local-ed25519-1")
    deployment_id = os.environ.get("THREATSIGHT_DEPLOYMENT_ID", DEFAULT_DEPLOYMENT_ID)
    provider = FileEd25519Provider(key_path=key_path, key_id=key_id)
    ok, reason = provider.ready()
    if not ok:
        return False, reason
    try:
        with Session(get_engine()) as db:
            policy = ensure_policy(db, deployment_id)
            db.commit()
            if policy.kill_switch:
                return True, "kill_switch"
    except Exception:
        return False, "database_unavailable"
    return True, "ok"


def _bootstrap_public_key(provider: FileEd25519Provider, *, deployment_id: str, worker_id: str) -> None:
    """Register and activate public metadata only. Never writes private key material."""
    ok, _ = provider.ready()
    if not ok:
        return
    material = provider.public_material()
    with Session(get_engine()) as db:
        ensure_policy(db, deployment_id)
        workspace = db.scalar(select(Workspace).where(Workspace.status == "active").order_by(Workspace.created_at.asc()))
        if workspace is None:
            db.commit()
            return
        register_public_key(
            db,
            key_id=material.key_id,
            deployment_id=deployment_id,
            public_key_pem=material.public_key_pem,
            fingerprint=material.fingerprint,
            provider_type=material.provider_type,
            maturity="fixture_tested",
            actor=worker_id,
            tenant_id=workspace.tenant_id,
            workspace_id=workspace.id,
        )
        key = db.scalar(select(EvidenceSigningKey).where(EvidenceSigningKey.key_id == material.key_id))
        if key is not None and key.status == "pending":
            activate_key(
                db,
                key_id=material.key_id,
                deployment_id=deployment_id,
                actor=worker_id,
                tenant_id=workspace.tenant_id,
                workspace_id=workspace.id,
            )
        db.commit()


def run_forever() -> None:
    key_path = Path(os.environ.get("THREATSIGHT_EVIDENCE_SIGNING_KEY_FILE", "/run/secrets/evidence_signing_key"))
    key_id = os.environ.get("THREATSIGHT_EVIDENCE_SIGNING_KEY_ID", "local-ed25519-1")
    deployment_id = os.environ.get("THREATSIGHT_DEPLOYMENT_ID", DEFAULT_DEPLOYMENT_ID)
    poll = float(os.environ.get("THREATSIGHT_SIGNER_POLL_SECONDS", "2"))
    worker_id = f"signer:{socket.gethostname()}:{os.getpid()}"
    provider = FileEd25519Provider(key_path=key_path, key_id=key_id)
    provider.load()
    try:
        _bootstrap_public_key(provider, deployment_id=deployment_id, worker_id=worker_id)
    except Exception:
        pass
    while True:
        _touch_alive()
        ok, reason = provider.ready()
        if not ok:
            time.sleep(poll)
            continue
        try:
            with Session(get_engine()) as db:
                request = claim_pending_request(db, worker_id=worker_id, deployment_id=deployment_id)
                if request is None:
                    db.commit()
                    time.sleep(poll)
                    continue
                try:
                    process_request(db, request, provider, deployment_id=deployment_id)
                    db.commit()
                except Exception as exc:  # noqa: BLE001 — preserve request, never leak key
                    db.rollback()
                    with Session(get_engine()) as retry:
                        row = retry.get(type(request), request.id)
                        if row is not None:
                            code = str(exc)[:64] or "signing_failed"
                            if code in {"signing_kill_switch", "inactive_key", "action_not_closed", "manifest_digest_mismatch", "missing_object"}:
                                fail_request(retry, row, code, worker_id)
                            else:
                                row.state = "pending"
                                row.error_code = "transient_error"
                                row.lease_owner = None
                                row.lease_until = None
                                retry.flush()
                            retry.commit()
        except Exception:
            time.sleep(poll)
            continue
        time.sleep(0.1)


def main() -> None:
    run_forever()


if __name__ == "__main__":
    main()
