"""Revoke sessions for the recovery administrator. It does not print secrets."""

from __future__ import annotations

import os
import sys

from threatsight_api.local_auth.service import account_in_tenant, revoke_sessions
from threatsight_api.persistence.models import Tenant
from threatsight_api.persistence.session import SessionLocal, configure_engine
from sqlalchemy import select


def main() -> int:
    if len(sys.argv) != 1 or os.environ.get("THREATSIGHT_OWNER_PASSWORD"):
        print("Refusing arguments and password environment variables.", file=sys.stderr)
        return 2
    if not sys.stdin.isatty():
        print("Run this command from an interactive terminal.", file=sys.stderr)
        return 2
    email = input("Owner email: ").strip()
    configure_engine()
    with SessionLocal() as db:
        tenant = db.scalar(select(Tenant).where(Tenant.key == "default", Tenant.status == "active"))
        if tenant is None:
            print("The default tenant is unavailable.", file=sys.stderr)
            return 1
        found = account_in_tenant(db, email=email, tenant_id=tenant.id)
        if found is None:
            print("Recovery was not completed.", file=sys.stderr)
            return 1
        credential, membership = found
        if membership.role != "platform-admin" or not credential.enabled:
            print("Recovery was not completed.", file=sys.stderr)
            return 1
        revoke_sessions(db, credential.identity_id)
        db.commit()
    print("Owner sessions revoked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())