"""Real Chromium + packaged UI + API; no AWS, remote requests or saved browser traces."""

import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn
from incident_investigator.main import create_app
from incident_investigator.security.http import RuntimeSettings
from incident_investigator.security.sessions import Sessions
from playwright.sync_api import Page, expect, sync_playwright


@pytest.fixture
def server() -> Iterator[tuple[str, Sessions]]:
    sessions = Sessions()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        settings = RuntimeSettings(api_port=port)
        application = create_app(settings, sessions, Path("apps/web/dist"))
        runner = uvicorn.Server(uvicorn.Config(application, access_log=False, log_level="critical"))
        thread = threading.Thread(target=runner.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        deadline = time.monotonic() + 10
        while not runner.started:
            if time.monotonic() >= deadline or not thread.is_alive():
                raise RuntimeError("test server failed to start")
            time.sleep(0.01)
        try:
            yield f"http://127.0.0.1:{port}", sessions
        finally:
            runner.should_exit = True
            thread.join(timeout=10)
            assert not thread.is_alive()


@pytest.fixture
def page() -> Iterator[Page]:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context(service_workers="block")
        context.route(
            "**/*",
            lambda route: (
                route.continue_()
                if route.request.url.startswith("http://127.0.0.1:")
                else route.abort()
            ),
        )
        try:
            yield context.new_page()
        finally:
            context.close()
            browser.close()


def test_pairing_is_memory_only_and_logout_revokes(
    page: Page, server: tuple[str, Sessions]
) -> None:
    origin, sessions = server
    requests: list[str] = []
    messages: list[str] = []
    page.on("request", lambda request: requests.append(request.url))
    page.on("console", lambda message: messages.append(message.text))
    secret = sessions.issue_pairing()
    page.goto(origin)
    page.get_by_label("Pairing code from the app terminal").fill(secret)
    with page.expect_response("**/api/v1/session") as exchanged:
        page.get_by_role("button", name="Unlock console").click()
    token = exchanged.value.json()["token"]
    expect(page.get_by_role("heading", name="Foundation ready")).to_be_visible()
    assert page.evaluate("() => [localStorage.length, sessionStorage.length]") == [0, 0]
    assert page.context.cookies() == []
    assert not any(secret in item or token in item for item in requests + messages)
    page.get_by_role("button", name="Lock console").click()
    expect(page.get_by_role("button", name="Unlock console")).to_be_visible()
    assert (
        page.request.get(
            origin + "/api/v1/session", headers={"Authorization": f"Bearer {token}"}
        ).status
        == 401
    )
    page.get_by_label("Pairing code from the app terminal").fill(sessions.issue_pairing())
    page.get_by_role("button", name="Unlock console").click()
    expect(page.get_by_role("heading", name="Foundation ready")).to_be_visible()
    page.reload()
    expect(page.get_by_role("button", name="Unlock console")).to_be_visible()


def test_real_browser_csrf_and_csp(page: Page, server: tuple[str, Sessions]) -> None:
    origin, sessions = server
    secret = sessions.issue_pairing()
    # An opaque origin cannot redeem the terminal code, even if an attacker knows it.
    page.goto("about:blank")
    result = page.evaluate(
        """async ({origin, secret}) => {
        try { return (await fetch(origin + '/api/v1/session', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({secret})
        })).status; } catch { return 'blocked'; }
    }""",
        {"origin": origin, "secret": secret},
    )
    assert result == "blocked"
    response = page.goto(origin)
    assert response is not None
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    # Production policy blocks inline script and event-handler execution.
    page.evaluate("""() => {
        const script = document.createElement('script');
        script.textContent = "document.body.dataset.compromised = 'true'";
        document.body.append(script);
        const image = document.createElement('img');
        image.setAttribute('onerror', "document.body.dataset.compromised = 'true'");
        image.src = '/missing-image'; document.body.append(image);
    }""")
    assert page.locator("body").get_attribute("data-compromised") is None
    # The failed cross-site attempt did not consume the pairing secret.
    assert sessions.redeem(secret)
