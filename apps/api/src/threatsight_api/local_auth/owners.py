"""List recovery administrators without password hashes or session material."""

from __future__ import annotations

from sqlalchemy import select

from threatsight_api.persistence.models import LocalCredential, Tenant, TenantMembership
from threatsight_api.persistence.session import SessionLocal, configure_engine


def main() -> int:
    configure_engine()
    with SessionLocal() as db:
        rows = db.execute(
            select(LocalCredential.email, LocalCredential.enabled, Tenant.key)
            .join(TenantMembership, TenantMembership.identity_id == LocalCredential.identity_id)
            .join(Tenant, Tenant.id == TenantMembership.tenant_id)
            .where(TenantMembership.role == "platform-admin")
            .order_by(LocalCredential.email)
        ).all()
    print(f"recovery_administrators={len(rows)}")
    for email, enabled, tenant_key in rows:
        print(f"email={email} enabled={str(enabled).lower()} tenant={tenant_key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
