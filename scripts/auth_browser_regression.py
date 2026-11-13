"""Disposable browser regression for logout. Never targets the preserved database."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright
from sqlalchemy import select
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps/api/src"))

from threatsight_api.local_auth.service import create_account  # noqa: E402
from threatsight_api.oidc import hash_opaque  # noqa: E402
from threatsight_api.persistence.models import AuthSession, Tenant, Workspace  # noqa: E402
from threatsight_api.persistence.session import get_engine  # noqa: E402
from threatsight_api.test_database import drop_isolated_database, provision_isolated_database  # noqa: E402
from threatsight_api.config import get_settings  # noqa: E402

PASSWORD = "a correct horse battery staple"
EMAIL = "browser-logout@example.com"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_http(url: str) -> None:
    import urllib.request

    for _ in range(240):
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status < 500:
                    return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("service did not become reachable")


def cookie_metadata(cookies: list[dict]) -> list[dict]:
    visible = []
    for cookie in cookies:
        if not str(cookie.get("name", "")).startswith("threatsight_") and not str(cookie.get("name", "")).startswith("__Host-threatsight_"):
            continue
        visible.append(
            {
                "name": cookie.get("name"),
                "path": cookie.get("path"),
                "domain_present": bool(cookie.get("domain")),
                "secure": bool(cookie.get("secure")),
                "httpOnly": bool(cookie.get("httpOnly")),
                "sameSite": cookie.get("sameSite"),
                "expires": cookie.get("expires"),
            }
        )
    return visible


def main() -> int:
    server_url = os.environ["THREATSIGHT_DATABASE_URL"]
    name, isolated = provision_isolated_database(server_url)
    os.environ["THREATSIGHT_DATABASE_URL"] = isolated
    get_settings.cache_clear()
    os.environ["THREATSIGHT_AUTH_MODE"] = "local"
    os.environ["THREATSIGHT_PUBLIC_DEMO"] = "false"
    os.environ["THREATSIGHT_ENV"] = "development"
    api_port = free_port()
    web_port = free_port()
    web_origin = f"http://localhost:{web_port}"
    os.environ["THREATSIGHT_CORS_ORIGINS"] = web_origin
    os.environ["THREATSIGHT_WEB_ORIGINS"] = web_origin
    os.environ["API_INTERNAL_URL"] = f"http://127.0.0.1:{api_port}"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "apps/api/src")
    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "threatsight_api.main:app", "--host", "127.0.0.1", "--port", str(api_port)],
        cwd=str(ROOT),
        env=env,
    )
    web = None
    try:
        wait_http(f"http://127.0.0.1:{api_port}/health")
        with Session(get_engine()) as db:
            tenant = db.scalar(select(Tenant).where(Tenant.key == "default"))
            workspace = db.scalar(select(Workspace).where(Workspace.key == "default"))
            create_account(db, email=EMAIL, password=PASSWORD, role="operator", tenant=tenant, workspace=workspace)
            db.commit()
        web = subprocess.Popen(
            ["npx", "next", "start", "--hostname", "127.0.0.1", "--port", str(web_port)],
            cwd=str(ROOT / "apps/web"),
            env=env,
        )
        wait_http(f"{web_origin}/login")
        chromium = sorted(Path.home().glob(".cache/ms-playwright/chromium-*/chrome-linux64/chrome"))[-1]
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=str(chromium), headless=True)
            context = browser.new_context()
            page = context.new_page()
            hosts: list[str] = []
            page.on(
                "framenavigated",
                lambda frame: hosts.append(frame.url.split("/")[2])
                if frame == page.main_frame and frame.url.startswith("http")
                else None,
            )
            page.goto(f"{web_origin}/login")
            opened = page.url.split("/")[2]
            page.get_by_label("Email").fill(EMAIL)
            page.get_by_label("Password").fill(PASSWORD)
            page.get_by_role("button", name="Sign in", exact=True).click()
            page.wait_for_url("**/demo")
            second = context.new_page()
            second.goto(f"{web_origin}/services")
            assert "/login" not in second.url
            page.get_by_role("button", name="Log out").click()
            page.wait_for_url("**/login**", timeout=60000)
            second.reload()
            second.wait_for_url("**/login**")
            page.go_back()
            page.wait_for_url("**/login**", timeout=60000)
            assert page.get_by_role("heading", name="Already signed in").count() == 0
            stale = context.request.get(f"{web_origin}/api/v1/radar/workspace")
            assert stale.status == 401
            time.sleep(3)
            page.reload()
            assert "/login" in page.url
            page.get_by_role("button", name="Log out").count()
            status = context.request.get(f"{web_origin}/api/v1/auth/status")
            assert status.status == 200
            assert "set-cookie" not in {key.lower() for key in status.headers}
            page.get_by_label("Email").fill(EMAIL)
            page.get_by_label("Password").fill(PASSWORD)
            page.get_by_role("button", name="Sign in", exact=True).click()
            page.wait_for_url("**/demo")
            assert page.url.split("/")[2] == opened
            assert set(hosts) == {opened}
            with page.expect_response("**/api/v1/auth/logout", timeout=20000) as logged_out:
                page.get_by_role("button", name="Log out").click()
            assert logged_out.value.status == 204
            page.wait_for_url("**/login**", timeout=20000)
            direct = context.request.get(f"{web_origin}/demo", max_redirects=0)
            assert direct.status in {307, 302}
            location = direct.headers.get("location", "")
            assert location.startswith("/") or location.startswith(web_origin)
            print("cookie_metadata", cookie_metadata(context.cookies()))
            browser.close()
        with Session(get_engine()) as db:
            rows = list(db.scalars(select(AuthSession)))
            assert rows
            assert all(row.revoked_at is not None for row in rows)
            assert all(len(row.token_hash) == 64 for row in rows)
            assert hash_opaque("placeholder") != rows[0].token_hash
        print("browser_regression_passed")
        return 0
    finally:
        if web is not None:
            web.terminate()
        api.terminate()
        drop_isolated_database(server_url, name)


if __name__ == "__main__":
    raise SystemExit(main())
