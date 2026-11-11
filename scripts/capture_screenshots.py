"""Regenerate the README screenshots in docs/screenshots.

Runs the real launcher against an isolated temporary workspace, loads the
synthetic guided demo, and captures each page with Playwright. Requires
requirements-dev.txt and `python -m playwright install chromium`, or set
SENTINELFLOW_CHROME to an installed Chrome executable.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "screenshots"
CHROME = os.environ.get("SENTINELFLOW_CHROME")
VIEWPORT = {"width": 1440, "height": 900}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_ready(base: str, process: subprocess.Popen) -> None:
    for _ in range(100):
        try:
            urllib.request.urlopen(base, timeout=0.5).close()
            return
        except OSError:
            if process.poll() is not None:
                raise RuntimeError("Launcher exited unexpectedly.") from None
            time.sleep(0.1)
    raise RuntimeError("Launcher did not become ready.")


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sentinelflow-shots-") as tmp:
        port = free_port()
        base = f"http://127.0.0.1:{port}"
        env = dict(os.environ, SENTINELFLOW_DATA=tmp, PORT=str(port))
        process = subprocess.Popen(
            [sys.executable, "run.py"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            wait_ready(base, process)
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True, args=["--no-sandbox"], executable_path=CHROME
                )
                context = browser.new_context(viewport=VIEWPORT, device_scale_factor=1)
                page = context.new_page()
                page.add_init_script("localStorage.setItem('sentinelflow-theme','dark')")

                def shot(name: str, path: str | None = None, settle: int = 600, full=False):
                    if path is not None:
                        page.goto(base + path, wait_until="networkidle")
                    page.wait_for_timeout(settle)
                    page.screenshot(path=str(OUTPUT / f"{name}.png"), full_page=full)
                    print("captured", name)

                page.goto(base + "/setup", wait_until="domcontentloaded")
                shot("sign-in", settle=900)
                page.locator("[name=email]").fill("analyst@example.com")
                page.locator("[name=username]").fill("analyst")
                page.locator("[name=password]").fill("ScreenshotPassword123")
                page.get_by_role("button", name="Create workspace").click()
                page.goto(base + "/replay", wait_until="domcontentloaded")
                page.get_by_role("button", name="Load guided demo").first.click()
                page.get_by_role("combobox", name="Replay speed").first.select_option("8")
                page.get_by_role("button", name="Start replay", exact=True).click()
                expect(page.get_by_text("finished").first).to_be_visible(timeout=30000)

                # Triage a couple of alerts so the inbox shows a realistic mix.
                for aid, status, note in [
                    (1, "investigating", "Confirming whether 10.0.0.51 is an authorized scanner."),
                    (3, "false_positive", "Known vulnerability scan window."),
                ]:
                    page.goto(f"{base}/alerts/{aid}", wait_until="domcontentloaded")
                    page.locator("[name=status]").select_option(status)
                    page.locator("[name=note]").fill(note)
                    page.get_by_role("button", name="Save investigation").click()

                shot("overview", "/", settle=1200)
                shot("alerts", "/alerts")
                alert = page.evaluate(
                    "fetch('/api/snapshot').then(r=>r.json()).then(s=>s.alerts.find(a=>a.rule==='beaconing').id)"
                )
                shot("alert-detail", f"/alerts/{alert}")
                page.goto(base + "/replay", wait_until="networkidle")
                page.wait_for_timeout(600)
                page.locator(".panel", has=page.locator(".session-list")).screenshot(
                    path=str(OUTPUT / "replay-timeline.png")
                )
                print("captured replay-timeline")
                shot("hosts", "/hosts", settle=5500)
                shot("host-detail", "/hosts/10.0.0.45")
                shot("analytics", "/analytics", settle=1200)
                shot("rules", "/rules")

                page.goto(base + "/", wait_until="networkidle")
                page.wait_for_timeout(800)
                page.keyboard.press("Control+k")
                page.locator("#palette-input").fill("")
                shot("command-palette", settle=400)
                page.keyboard.press("Escape")

                page.evaluate("localStorage.setItem('sentinelflow-theme','light')")
                context.add_init_script("localStorage.setItem('sentinelflow-theme','light')")
                shot("overview-light", "/", settle=1200)
                shot("analytics-light", "/analytics", settle=1200)

                mobile = browser.new_context(
                    viewport={"width": 390, "height": 844}, device_scale_factor=2
                )
                mobile.add_cookies(context.cookies())
                phone = mobile.new_page()
                phone.add_init_script("localStorage.setItem('sentinelflow-theme','dark')")
                phone.goto(base + "/", wait_until="networkidle")
                phone.wait_for_timeout(1200)
                phone.screenshot(path=str(OUTPUT / "mobile.png"))
                print("captured mobile")
                browser.close()
        finally:
            process.terminate()
            process.wait(timeout=10)


if __name__ == "__main__":
    main()
