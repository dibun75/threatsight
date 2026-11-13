"""Interactive owner bootstrap. It refuses passwords in arguments or the environment."""

from __future__ import annotations

import getpass
import os
import sys

from sqlalchemy import select

from threatsight_api.config import get_settings
from threatsight_api.local_auth.passwords import PasswordRejected
from threatsight_api.local_auth.service import LocalAuthError, create_account, enabled_owner_count
from threatsight_api.persistence.models import Tenant, Workspace
from threatsight_api.persistence.session import SessionLocal, configure_engine


def main() -> int:
    if len(sys.argv) != 1 or os.environ.get("THREATSIGHT_OWNER_PASSWORD") or os.environ.get("THREATSIGHT_OWNER_EMAIL"):
        print("Refusing arguments and password environment variables.", file=sys.stderr)
        return 2
    if not sys.stdin.isatty():
        print("Run this command from an interactive terminal.", file=sys.stderr)
        return 2
    email = input("Owner email: ").strip()
    password = getpass.getpass("Owner password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords did not match.", file=sys.stderr)
        return 1
    configure_engine()
    settings = get_settings()
    try:
        with SessionLocal() as db:
            tenant = db.scalar(select(Tenant).where(Tenant.key == "default", Tenant.status == "active"))
            workspace = db.scalar(select(Workspace).where(Workspace.key == settings.default_workspace_key, Workspace.status == "active"))
            if tenant is None or workspace is None:
                print("The default tenant or workspace is unavailable.", file=sys.stderr)
                return 1
            if enabled_owner_count(db, tenant.id):
                print("An owner already exists.", file=sys.stderr)
                return 1
            create_account(db, email=email, password=password, role="platform-admin", tenant=tenant, workspace=workspace)
            db.commit()
    except LocalAuthError as exc:
        print(exc.detail, file=sys.stderr)
        return 1
    except PasswordRejected:
        print("Owner was not created.", file=sys.stderr)
        return 1
    print("Owner created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
