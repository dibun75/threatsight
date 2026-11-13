import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from threatsight_api.config import get_settings

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}
PASSWORD = "a correct horse battery staple"
OTHER = "another correct horse battery"


pytestmark = pytest.mark.skipif(not LIVE, reason="requires live postgres")


@pytest.fixture(autouse=True)
def _clear_settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("THREATSIGHT_AUTH_MODE", "local")
    monkeypatch.setenv("THREATSIGHT_PUBLIC_DEMO", "false")
    monkeypatch.setenv("THREATSIGHT_CORS_ORIGINS", "http://testserver")
    get_settings.cache_clear()
    from threatsight_api.main import app

    return TestClient(app)


def _headers(client: TestClient) -> dict[str, str]:
    return {"Origin": "http://testserver", "X-CSRF-Token": client.cookies.get("threatsight_csrf") or ""}


def _owner(client: TestClient) -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from threatsight_api.local_auth.service import create_account
    from threatsight_api.persistence.models import Tenant, Workspace
    from threatsight_api.persistence.session import get_engine

    with Session(get_engine()) as db:
        tenant = db.scalar(select(Tenant).where(Tenant.key == "default"))
        workspace = db.scalar(select(Workspace).where(Workspace.key == "default"))
        create_account(db, email="owner@example.com", password=PASSWORD, role="platform-admin", tenant=tenant, workspace=workspace)
        db.commit()
    assert client.post("/api/v1/auth/local/login", json={"email": "owner@example.com", "password": PASSWORD}).status_code == 200


def test_local_login_boundaries_and_revocation(monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from threatsight_api.local_auth.service import create_account
    from threatsight_api.oidc import hash_opaque, resolve_session
    from threatsight_api.persistence.models import AuthSession, LocalAuthThrottle, LocalCredential, Tenant, Workspace, WorkspaceMembership
    from threatsight_api.persistence.session import get_engine

    with _client(monkeypatch) as client:
        assert client.get("/health").status_code == 200
        denied = client.get("/api/v1/radar/workspace", headers={"X-Actor": "demo-viewer", "X-Role": "platform-admin", "X-Forwarded-For": "203.0.113.50"})
        assert denied.status_code == 401
        assert "demo-viewer" not in denied.text
        _owner(client)
        wrong_email = client.post("/api/v1/auth/local/login", json={"email": "missing@example.com", "password": OTHER})
        wrong_password = client.post("/api/v1/auth/local/login", json={"email": "owner@example.com", "password": OTHER})
        assert wrong_email.status_code == wrong_password.status_code == 401
        assert wrong_email.json() == wrong_password.json()
        assert PASSWORD not in wrong_password.text and "$argon2" not in wrong_password.text
        with Session(get_engine()) as db:
            assert db.get(LocalAuthThrottle, hash_opaque("source:203.0.113.50")) is None
        planted = {"threatsight_session": "attacker-session"}
        rotated = client.post("/api/v1/auth/local/login", json={"email": "owner@example.com", "password": PASSWORD}, cookies=planted)
        assert rotated.status_code == 200
        assert rotated.cookies.get("threatsight_session") != "attacker-session"
        viewer = client.post(
            "/api/v1/auth/local/accounts",
            json={"email": "viewer@example.com", "role": "viewer"},
            headers=_headers(client),
        )
        assert viewer.status_code == 200
        raw = viewer.json()["token"]
        assert raw not in str(client.get("/api/v1/auth/local/accounts").json())
        first = client.post("/api/v1/auth/local/activate", json={"token": raw, "password": PASSWORD})
        assert first.status_code == 200
        assert client.post("/api/v1/auth/local/activate", json={"token": raw, "password": PASSWORD}).status_code == 400
        client.cookies.clear()
        assert client.post("/api/v1/auth/local/login", json={"email": "viewer@example.com", "password": PASSWORD}).status_code == 200
        assert client.post("/api/v1/auth/local/accounts", json={"email": "x@example.com", "role": "platform-admin"}, headers=_headers(client)).status_code == 403
        client.cookies.clear()
        assert client.post("/api/v1/auth/local/login", json={"email": "owner@example.com", "password": PASSWORD}).status_code == 200
        without_csrf = client.post("/api/v1/auth/local/accounts/change", json={"email": "viewer@example.com", "enabled": False})
        assert without_csrf.status_code == 403
        changed = client.post(
            "/api/v1/auth/local/accounts/change",
            json={"email": "viewer@example.com", "role": "operator"},
            headers=_headers(client),
        )
        assert changed.status_code == 200
        self_change = client.post(
            "/api/v1/auth/local/accounts/change",
            json={"email": "owner@example.com", "role": "viewer"},
            headers=_headers(client),
        )
        assert self_change.status_code == 403
        last_admin = client.post(
            "/api/v1/auth/local/accounts/change",
            json={"email": "owner@example.com", "enabled": False},
            headers=_headers(client),
        )
        assert last_admin.status_code == 403
        with Session(get_engine()) as db:
            tenant = db.scalar(select(Tenant).where(Tenant.key == "default"))
            other = Workspace(tenant_id=tenant.id, key=f"other-{uuid.uuid4().hex[:8]}", name="Other")
            db.add(other)
            db.flush()
            create_account(db, email="other@example.com", password=PASSWORD, role="viewer", tenant=tenant, workspace=other)
            outsider = Tenant(key=f"other-{uuid.uuid4().hex[:8]}", name="Other tenant")
            db.add(outsider)
            db.flush()
            foreign = Workspace(tenant_id=outsider.id, key=f"foreign-{uuid.uuid4().hex[:8]}", name="Foreign")
            db.add(foreign)
            db.flush()
            create_account(db, email="foreign@example.com", password=PASSWORD, role="platform-admin", tenant=outsider, workspace=foreign)
            db.commit()
        hidden = client.post(
            "/api/v1/auth/local/accounts/change",
            json={"email": "foreign@example.com", "enabled": False},
            headers=_headers(client),
        )
        assert hidden.status_code == 404
        listed = client.get("/api/v1/auth/local/accounts").json()["items"]
        assert "foreign@example.com" not in {item["email"] for item in listed}
        disabled = client.post(
            "/api/v1/auth/local/accounts/change",
            json={"email": "other@example.com", "enabled": False},
            headers=_headers(client),
        )
        assert disabled.status_code == 200
        client.cookies.clear()
        assert client.post("/api/v1/auth/local/login", json={"email": "other@example.com", "password": PASSWORD}).status_code == 401
        assert client.post("/api/v1/auth/local/login", json={"email": "owner@example.com", "password": PASSWORD}).status_code == 200
        reset = client.post("/api/v1/auth/local/accounts/reset", json={"email": "other@example.com", "role": "viewer"}, headers=_headers(client))
        assert reset.status_code == 200
        reset_token = reset.json()["token"]
        client.cookies.clear()
        assert client.post("/api/v1/auth/local/reset", json={"token": reset_token, "password": OTHER}).status_code == 200
        assert client.post("/api/v1/auth/local/reset", json={"token": reset_token, "password": OTHER}).status_code == 400
        assert client.post("/api/v1/auth/local/login", json={"email": "other@example.com", "password": PASSWORD}).status_code == 401
        assert client.post("/api/v1/auth/local/login", json={"email": "other@example.com", "password": OTHER}).status_code == 200
        old = client.cookies.get("threatsight_session")
        assert client.post("/api/v1/auth/logout", headers=_headers(client), follow_redirects=False).status_code in {200, 204, 303}
        client.cookies.clear()
        assert client.get("/api/v1/radar/workspace", cookies={"threatsight_session": old}).status_code == 401
        assert client.post("/api/v1/auth/local/login", json={"email": "other@example.com", "password": OTHER}).status_code == 200
        current = client.cookies.get("threatsight_session")
        with Session(get_engine()) as db:
            record = db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_opaque(current)))
            record.last_seen_at = datetime.now(UTC) - timedelta(hours=2)
            db.commit()
            assert resolve_session(db, current) is None
            credential = db.scalar(select(LocalCredential).where(LocalCredential.email == "viewer@example.com"))
            membership = db.scalar(select(WorkspaceMembership).where(WorkspaceMembership.identity_id == credential.identity_id))
            db.delete(membership)
            db.commit()
        assert client.post("/api/v1/auth/local/login", json={"email": "viewer@example.com", "password": PASSWORD}).status_code == 401
        for _ in range(5):
            client.post("/api/v1/auth/local/login", json={"email": "missing@example.com", "password": OTHER})
        locked = client.post("/api/v1/auth/local/login", json={"email": "missing@example.com", "password": OTHER})
        assert locked.status_code == 429


def test_session_context_logout_and_disablement(monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from threatsight_api.local_auth.service import create_account
    from threatsight_api.oidc import hash_opaque
    from threatsight_api.persistence.models import AuthSession, LocalAuthThrottle, Tenant, Workspace
    from threatsight_api.persistence.session import get_engine

    email = f"session-{uuid.uuid4().hex[:8]}@example.com"
    with _client(monkeypatch) as client:
        assert client.get("/api/v1/auth/session").status_code == 401
        with Session(get_engine()) as db:
            for row in db.scalars(select(LocalAuthThrottle)):
                row.failures = 0
                row.locked_until = None
            tenant = db.scalar(select(Tenant).where(Tenant.key == "default"))
            workspace = db.scalar(select(Workspace).where(Workspace.key == "default"))
            create_account(db, email=email, password=PASSWORD, role="viewer", tenant=tenant, workspace=workspace)
            create_account(db, email=f"operator-{email}", password=PASSWORD, role="operator", tenant=tenant, workspace=workspace)
            create_account(db, email=f"admin-{email}", password=PASSWORD, role="platform-admin", tenant=tenant, workspace=workspace)
            db.commit()
        for account, role in ((email, "viewer"), (f"operator-{email}", "operator"), (f"admin-{email}", "platform-admin")):
            client.cookies.clear()
            assert client.post("/api/v1/auth/local/login", json={"email": account, "password": PASSWORD}).status_code == 200
            presented = client.get("/api/v1/auth/session")
            assert presented.status_code == 200
            assert presented.json()["role"] == role
            assert client.post("/api/v1/auth/logout", headers=_headers(client)).status_code == 204
        assert client.post("/api/v1/auth/local/login", json={"email": email, "password": PASSWORD}).status_code == 200
        context = client.get(
            "/api/v1/auth/session",
            headers={"X-Actor": "demo-viewer", "X-Role": "platform-admin", "X-Workspace-Key": "foreign"},
        )
        assert context.status_code == 200
        body = context.json()
        assert body["role"] == "viewer"
        assert body["workspace_key"] == "default"
        assert body["account"] == email
        assert body["logout_available"] is True
        assert context.headers["cache-control"] == "no-store"
        assert "token_hash" not in body and "password" not in context.text and "$argon" not in context.text
        assert client.get("/api/v1/auth/logout").status_code == 405
        denied = client.post("/api/v1/auth/logout")
        assert denied.status_code == 403
        raw = client.cookies.get("threatsight_session")
        from fastapi.testclient import TestClient
        from threatsight_api.main import create_app

        fresh = TestClient(create_app())
        fresh.cookies.set("threatsight_session", raw)
        assert fresh.get("/api/v1/auth/session").status_code == 200
        logged_out = client.post("/api/v1/auth/logout", headers=_headers(client))
        assert logged_out.status_code == 204
        assert "max-age=0" in logged_out.headers.get("set-cookie", "").lower()
        assert client.get("/api/v1/auth/session", cookies={"threatsight_session": raw}).status_code == 401
        assert client.post("/api/v1/auth/logout", headers=_headers(client), cookies={"threatsight_session": raw}).status_code == 403
        with Session(get_engine()) as db:
            record = db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_opaque(raw)))
            assert record.revoked_at is not None
        assert client.post("/api/v1/auth/local/login", json={"email": email, "password": PASSWORD}).status_code == 200
        with Session(get_engine()) as db:
            from threatsight_api.persistence.models import LocalCredential

            credential = db.scalar(select(LocalCredential).where(LocalCredential.email == email))
            credential.enabled = False
            db.commit()
        assert client.get("/api/v1/auth/session").status_code == 401


def test_logout_uses_the_configured_browser_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from threatsight_api.local_auth.service import create_account
    from threatsight_api.oidc import hash_opaque
    from threatsight_api.persistence.models import AuthSession, LocalAuthThrottle, Tenant, Workspace
    from threatsight_api.persistence.session import get_engine

    monkeypatch.setenv("THREATSIGHT_WEB_ORIGINS", "https://threatsight.io")
    email = f"origin-{uuid.uuid4().hex[:8]}@example.com"
    with _client(monkeypatch) as client:
        with Session(get_engine()) as db:
            for row in db.scalars(select(LocalAuthThrottle)):
                row.failures = 0
                row.locked_until = None
            tenant = db.scalar(select(Tenant).where(Tenant.key == "default"))
            workspace = db.scalar(select(Workspace).where(Workspace.key == "default"))
            create_account(db, email=email, password=PASSWORD, role="viewer", tenant=tenant, workspace=workspace)
            db.commit()
        assert client.post("/api/v1/auth/local/login", json={"email": email, "password": PASSWORD}).status_code == 200
        raw = client.cookies.get("threatsight_session")
        headers = _headers(client)
        rejected = client.post("/api/v1/auth/logout", headers={**headers, "Origin": "https://evil.example"})
        assert rejected.status_code == 403
        assert client.get("/api/v1/auth/session").status_code == 200
        missing = client.post("/api/v1/auth/logout", headers={"Origin": "https://threatsight.io"})
        assert missing.status_code == 403
        logged_out = client.post("/api/v1/auth/logout", headers={**headers, "Origin": "https://threatsight.io"})
        assert logged_out.status_code == 204
        assert "max-age=0" in logged_out.headers.get("set-cookie", "").lower()
        assert "threatsight_session=" not in logged_out.text
        with Session(get_engine()) as db:
            record = db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_opaque(raw)))
            assert record.revoked_at is not None
        assert client.get("/api/v1/auth/session", cookies={"threatsight_session": raw}).status_code == 401
        assert client.post("/api/v1/auth/logout", headers={**headers, "Origin": "https://threatsight.io"}, cookies={"threatsight_session": raw}).status_code == 403


def test_logout_revokes_every_presented_session_and_sets_no_new_one(monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from threatsight_api.local_auth.service import create_account
    from threatsight_api.oidc import create_session, hash_opaque
    from threatsight_api.persistence.models import AuthSession, Identity, LocalAuthThrottle, LocalCredential, Tenant, Workspace
    from threatsight_api.persistence.session import get_engine

    email = f"cookies-{uuid.uuid4().hex[:8]}@example.com"
    with _client(monkeypatch) as client:
        with Session(get_engine()) as db:
            for row in db.scalars(select(LocalAuthThrottle)):
                row.failures = 0
                row.locked_until = None
            tenant = db.scalar(select(Tenant).where(Tenant.key == "default"))
            workspace = db.scalar(select(Workspace).where(Workspace.key == "default"))
            create_account(db, email=email, password=PASSWORD, role="operator", tenant=tenant, workspace=workspace)
            tenant_id = tenant.id
            db.commit()
        assert client.post("/api/v1/auth/local/login", json={"email": email, "password": PASSWORD}).status_code == 200
        first = client.cookies.get("threatsight_session")
        csrf = client.cookies.get("threatsight_csrf")
        status = client.get("/api/v1/auth/status")
        assert status.status_code == 200
        assert status.headers.get("set-cookie") is None
        with Session(get_engine()) as db:
            identity = db.scalar(select(Identity).join(LocalCredential, LocalCredential.identity_id == Identity.id).where(LocalCredential.email == email))
            assert identity is not None
            second = create_session(db, identity=identity, tenant_id=tenant_id, role="operator", minutes=30)
            db.commit()
        client.cookies.clear()
        logged_out = client.post(
            "/api/v1/auth/logout",
            headers={
                "Origin": "http://testserver",
                "X-CSRF-Token": csrf,
                "Cookie": f"threatsight_session={first}; threatsight_session={second}; threatsight_csrf={csrf}",
            },
        )
        assert logged_out.status_code == 204
        deleted = logged_out.headers.get_list("set-cookie")
        assert len(deleted) >= 9
        assert all("1970" in item and "Max-Age=0" in item for item in deleted)
        assert all("Domain=" not in item for item in deleted)
        with Session(get_engine()) as db:
            hashes = {hash_opaque(first), hash_opaque(second)}
            rows = list(db.scalars(select(AuthSession).where(AuthSession.token_hash.in_(hashes))))
            assert len(rows) == 2
            assert all(row.revoked_at is not None for row in rows)
        again = client.post(
            "/api/v1/auth/logout",
            headers={"Origin": "http://testserver", "X-CSRF-Token": csrf, "Cookie": f"threatsight_session={first}; threatsight_csrf={csrf}"},
        )
        assert again.status_code == 204
        assert client.get("/api/v1/auth/session", headers={"Cookie": f"threatsight_session={first}"}).status_code == 401


def test_concurrent_logout_revokes_once(monkeypatch: pytest.MonkeyPatch) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from threatsight_api.local_auth.service import create_account
    from threatsight_api.oidc import hash_opaque
    from threatsight_api.persistence.models import AuthSession, LocalAuthThrottle, Tenant, Workspace
    from threatsight_api.persistence.session import get_engine

    email = f"race-{uuid.uuid4().hex[:8]}@example.com"
    with _client(monkeypatch) as client:
        with Session(get_engine()) as db:
            for row in db.scalars(select(LocalAuthThrottle)):
                row.failures = 0
                row.locked_until = None
            tenant = db.scalar(select(Tenant).where(Tenant.key == "default"))
            workspace = db.scalar(select(Workspace).where(Workspace.key == "default"))
            create_account(db, email=email, password=PASSWORD, role="viewer", tenant=tenant, workspace=workspace)
            db.commit()
        assert client.post("/api/v1/auth/local/login", json={"email": email, "password": PASSWORD}).status_code == 200
        token = client.cookies.get("threatsight_session")
        csrf = client.cookies.get("threatsight_csrf")
        client.cookies.clear()

        def once(_item: int) -> int:
            return client.post(
                "/api/v1/auth/logout",
                headers={"Origin": "http://testserver", "X-CSRF-Token": csrf, "Cookie": f"threatsight_session={token}; threatsight_csrf={csrf}"},
            ).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = sorted(pool.map(once, (1, 2)))
        assert outcomes == [204, 204]
        with Session(get_engine()) as db:
            record = db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_opaque(token)))
            assert record.revoked_at is not None


def test_bootstrap_refuses_arguments_and_a_second_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    from threatsight_api.local_auth import bootstrap

    monkeypatch.setattr(sys, "argv", ["bootstrap", "--password", "nope"])
    assert bootstrap.main() == 2
    monkeypatch.setattr(sys, "argv", ["bootstrap"])
    monkeypatch.setenv("THREATSIGHT_OWNER_PASSWORD", "present")
    assert bootstrap.main() == 2
    monkeypatch.delenv("THREATSIGHT_OWNER_PASSWORD")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert bootstrap.main() == 2
