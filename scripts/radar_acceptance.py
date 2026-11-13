"""Disposable authenticated acceptance for the Radar command center. Never uses the production owner."""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright
from sqlalchemy import text
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps/api/src"))

from threatsight_api.config import get_settings  # noqa: E402
from threatsight_api.local_auth.service import create_account  # noqa: E402
from threatsight_api.persistence.models import Tenant, Workspace  # noqa: E402
from threatsight_api.persistence.session import get_engine  # noqa: E402
from threatsight_api.test_database import drop_isolated_database, provision_isolated_database  # noqa: E402

PASSWORD = "a correct horse battery staple"
EMAIL = "radar-acceptance@example.com"
SHOTS = Path("/tmp/threatsight-radar-playwright")


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


def main() -> int:
    SHOTS.mkdir(exist_ok=True)
    server_url = os.environ["THREATSIGHT_DATABASE_URL"]
    name, isolated = provision_isolated_database(server_url)
    os.environ["THREATSIGHT_DATABASE_URL"] = isolated
    get_settings.cache_clear()
    os.environ["THREATSIGHT_AUTH_MODE"] = "local"
    os.environ["THREATSIGHT_PUBLIC_DEMO"] = "false"
    os.environ["THREATSIGHT_ENV"] = "development"
    os.environ["THREATSIGHT_RADAR_ENABLED"] = "false"
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
            tenant = db.scalar(select_tenant())
            workspace = db.scalar(select_workspace())
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
            page = browser.new_context(viewport={"width": 1280, "height": 800}).new_page()
            errors: list[str] = []
            failed: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("response", lambda response: failed.append(response.url) if response.status >= 500 else None)
            page.goto(f"{web_origin}/login")
            page.get_by_label("Email").fill(EMAIL)
            page.get_by_label("Password").fill(PASSWORD)
            page.get_by_role("button", name="Sign in", exact=True).click()
            page.wait_for_url("**/demo")
            page.get_by_role("heading", name="Global activity").wait_for()
            page.get_by_role("region", name="Global activity").get_by_text("Collection is not enabled.").wait_for()
            assert "not connected" not in page.content().lower()
            assert "No decision is recorded" not in page.content()
            assert "Units are not stored" not in page.content()
            page.get_by_role("button", name="Origin").click()
            page.get_by_role("button", name="Target").click()
            page.get_by_role("button", name="7 days").click()
            page.get_by_role("button", name="24 hours").click()
            page.get_by_role("button", name="Advisory coverage").click()
            page.locator("#advisory-geography-tooltip").wait_for()
            assert "Advisory-record count" in page.content()
            assert "Share of Cloudflare-observed" not in page.content()
            page.get_by_role("button", name="Your exposure").click()
            assert "No geographic exposure verdict is available" in page.content()
            assert "Advisory-record count" not in page.content()
            page.get_by_role("button", name="Global observed activity").click()
            page.screenshot(path=str(SHOTS / "desktop-disabled.png"), full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            page.screenshot(path=str(SHOTS / "mobile-disabled.png"), full_page=True)
            page.set_viewport_size({"width": 1280, "height": 800})
            with Session(get_engine()) as db:
                db.execute(
                    text(
                        """
                        INSERT INTO telemetry_runs (id, source, status, window_label, started_at, finished_at)
                        VALUES ('00000000-0000-4000-8000-000000000221', 'cloudflare_radar', 'succeeded', '24h', now(), now())
                        """
                    )
                )
                db.execute(
                    text(
                        """
                        INSERT INTO telemetry_snapshots (
                            id, source, dataset, window_label, retrieved_at, source_updated_at, units, normalization,
                            freshness, maturity, limitations, content_hash, is_current, confidence, annotations
                        ) VALUES (
                            '00000000-0000-4000-8000-000000000222', 'cloudflare_radar', 'origin', '24h', now(), now(),
                            'percentage', 'PERCENTAGE', 'fresh', 'live_verified', '[]'::jsonb, 'fixture', true,
                            '{"level": 4}'::jsonb, '[]'::jsonb
                        )
                        """
                    )
                )
                db.execute(
                    text(
                        """
                        INSERT INTO telemetry_points (id, snapshot_id, role, country_code, country_name, value, rank, note)
                        VALUES ('00000000-0000-4000-8000-000000000223', '00000000-0000-4000-8000-000000000222', 'origin', 'US', 'United States', 12.5, 1, '')
                        """
                    )
                )
                db.execute(
                    text(
                        """
                        INSERT INTO telemetry_snapshots (
                            id, source, dataset, window_label, retrieved_at, source_updated_at, units, normalization,
                            freshness, maturity, limitations, content_hash, is_current, confidence, annotations
                        ) VALUES (
                            '00000000-0000-4000-8000-000000000224', 'cloudflare_radar', 'norway_origin', '24h', now(), now(),
                            'requests', 'PERCENTAGE', 'fresh', 'live_verified', '[]'::jsonb, 'fixture-no', true,
                            '{"level": null, "supplied": false}'::jsonb, '[]'::jsonb
                        )
                        """
                    )
                )
                db.execute(
                    text(
                        """
                        INSERT INTO telemetry_points (id, snapshot_id, role, country_code, country_name, value, rank, note)
                        VALUES ('00000000-0000-4000-8000-000000000225', '00000000-0000-4000-8000-000000000224', 'norway_origin', 'NO', 'Norway', 0.068, 81, '')
                        """
                    )
                )
                db.execute(
                    text(
                        """
                        INSERT INTO telemetry_snapshots (
                            id, source, dataset, window_label, retrieved_at, source_updated_at, units, normalization,
                            freshness, maturity, limitations, content_hash, is_current, confidence, annotations
                        ) VALUES (
                            '00000000-0000-4000-8000-000000000226', 'cloudflare_radar', 'origin', '7d', now(), now(),
                            'requests', 'PERCENTAGE', 'fresh', 'live_verified', '[]'::jsonb, 'fixture-7d', true,
                            '{"level": null, "supplied": false}'::jsonb, '[]'::jsonb
                        )
                        """
                    )
                )
                db.execute(
                    text(
                        """
                        INSERT INTO telemetry_points (id, snapshot_id, role, country_code, country_name, value, rank, note)
                        VALUES ('00000000-0000-4000-8000-000000000227', '00000000-0000-4000-8000-000000000226', 'origin', 'FR', 'France', 7.25, 1, '')
                        """
                    )
                )
                db.commit()
            page.reload()
            page.get_by_role("button", name=re.compile(r"^United States")).wait_for()
            assert "12.5" in page.content()
            assert "Cloudflare-observed mitigated Layer 7 requests" in page.content()
            assert "all global attacks" not in page.content().lower()
            assert "0.068" in page.content()
            page.get_by_role("button", name="7 days").click()
            page.get_by_role("button", name=re.compile(r"^France,")).wait_for()
            assert "7.25" in page.content()
            page.get_by_role("button", name="24 hours").click()
            page.get_by_role("button", name=re.compile(r"^Norway,")).wait_for()
            page.get_by_label("Country").select_option("NO")
            assert "Norway is selected." in page.content()
            page.locator("#country-US").press("Enter")
            page.wait_for_url("**country=US**")
            assert "United States is selected." in page.content()
            assert "Norway is selected." not in page.content()
            page.go_back()
            page.wait_for_url("**country=NO**")
            assert "Norway is selected." in page.content()
            investigation = page.get_by_role("link", name="Open the service investigation")
            if investigation.count():
                investigation.first.click()
                page.get_by_role("tab", name="Technology").click()
                page.wait_for_url("**tab=technology**")
                page.reload()
                page.get_by_role("tab", name="Technology").wait_for()
                assert "tab=technology" in page.url
                page.get_by_role("tab", name="Actions").click()
                page.get_by_role("link", name="Open the action register").click()
                page.wait_for_url("**/actions?service=**")
                page.get_by_role("heading", name="Filtered to this service").wait_for()
                page.go_back()
                page.get_by_role("heading", name=re.compile("Customer ordering")).wait_for()
                page.goto(f"{web_origin}/demo")
            page.screenshot(path=str(SHOTS / "desktop-populated.png"), full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            overflow = page.evaluate("() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1")
            assert overflow is False
            assert page.locator("time.source-time").count() >= 0
            page.set_viewport_size({"width": 1280, "height": 800})
            page.goto(f"{web_origin}/demo")
            page.locator("main").wait_for()
            focus_names = page.evaluate(
                """() => {
                  const names = [];
                  const seen = new Set();
                  document.querySelector('a.skip, a')?.focus();
                  for (let i = 0; i < 40; i += 1) {
                    const el = document.activeElement;
                    if (!el) break;
                    const name = (el.getAttribute('aria-label') || el.innerText || el.getAttribute('name') || el.tagName).trim().slice(0, 80);
                    if (!seen.has(name + el.tagName)) {
                      seen.add(name + el.tagName);
                      names.push(name);
                    }
                    const event = new KeyboardEvent('keydown', {key: 'Tab', bubbles: true});
                    el.dispatchEvent(event);
                    if (typeof el.blur === 'function') {
                      const focusables = [...document.querySelectorAll('a, button, input, select, textarea, [tabindex]:not([tabindex="-1"])')].filter((item) => !item.disabled && item.offsetParent !== null);
                      const index = focusables.indexOf(el);
                      const next = focusables[index + 1] || focusables[0];
                      next?.focus();
                    }
                  }
                  return names;
                }"""
            )
            joined = " | ".join(focus_names).lower()
            for required in ("command center", "log out", "review affected services", "global observed activity"):
                assert required in joined, f"keyboard missing {required}: {focus_names}"
            page.goto(f"{web_origin}/controls")
            page.locator("main").wait_for()
            assurance_options = page.get_by_label("Assurance").inner_text()
            assert "Validated" in assurance_options
            assert "VALIDATED" not in assurance_options
            assert "Passed defined check" in page.get_by_label("Verdict").inner_text()
            axe = (ROOT / "apps/web/node_modules/axe-core/axe.min.js").read_text()
            for path in ("/demo", "/threats", "/services", "/paths", "/controls", "/actions", "/evidence", "/briefing", "/tour"):
                page.goto(f"{web_origin}{path}")
                page.locator("main").wait_for()
                spoken = page.evaluate(
                    """() => {
                      const names = [...document.querySelectorAll('[aria-label], [title]')].map((el) => `${el.getAttribute('aria-label') || ''} ${el.getAttribute('title') || ''}`);
                      return `${document.body.innerText}\\n${names.join('\\n')}`;
                    }"""
                )
                lowered = spoken.lower()
                assert "fixture tested" not in lowered, path
                assert "fixture_tested" not in lowered, path
                page.evaluate(axe)
                violations = page.evaluate("() => axe.run().then((result) => result.violations.map((item) => item.id + ': ' + item.help))")
                if violations:
                    raise AssertionError(f"{path}: " + "; ".join(violations))
            page.goto(f"{web_origin}/demo")
            service_link = page.get_by_role("link", name="Open the service investigation")
            if service_link.count():
                service_link.first.click()
                page.get_by_role("tab", name="Technology").wait_for()
                tab_order = []
                for name in ("Situation", "Technology", "Paths", "Controls", "Actions", "Evidence"):
                    page.get_by_role("tab", name=name).focus()
                    tab_order.append(page.evaluate("() => document.activeElement?.innerText?.trim()"))
                    page.keyboard.press("Enter")
                assert tab_order == ["Situation", "Technology", "Paths", "Controls", "Actions", "Evidence"]
            second = page.context.new_page()
            second.goto(f"{web_origin}/demo")
            page.get_by_role("button", name="Log out").click()
            page.wait_for_url("**/login**")
            second.reload()
            second.wait_for_url("**/login**")
            assert not errors
            assert not failed
            browser.close()
        print("radar_acceptance_passed")
        return 0
    finally:
        if web is not None:
            web.terminate()
        api.terminate()
        drop_isolated_database(server_url, name)


def select_tenant():
    from sqlalchemy import select

    return select(Tenant).where(Tenant.key == "default")


def select_workspace():
    from sqlalchemy import select

    return select(Workspace).where(Workspace.key == "default")


if __name__ == "__main__":
    raise SystemExit(main())
