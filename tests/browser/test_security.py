"""Real Chromium + packaged UI + API; no AWS, remote requests or saved browser traces."""

import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn
from incident_investigator.evaluation.golden import IncidentInput
from incident_investigator.main import create_app
from incident_investigator.security.authority import SecurityAuthority
from incident_investigator.security.http import RuntimeSettings
from incident_investigator.security.sessions import Sessions
from playwright.sync_api import Page, expect, sync_playwright


@pytest.fixture
def server(tmp_path: Path) -> Iterator[tuple[str, Sessions]]:
    sessions = Sessions()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        settings = RuntimeSettings(api_port=port)
        application = create_app(
            settings, sessions, Path("apps/web/dist"), SecurityAuthority(tmp_path / "runtime")
        )
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


def test_browser_can_investigate_stream_export_and_recall(
    page: Page, server: tuple[str, Sessions]
) -> None:
    origin, sessions = server
    page.goto(origin)
    source = IncidentInput.model_validate_json(
        Path("fixtures/evaluation/golden/v1/inputs/case-001.json").read_bytes()
    ).model_dump(mode="json")
    result = page.evaluate(
        """async ({secret, incident}) => {
        const paired = await fetch('/api/v1/session', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({secret})
        });
        const {token} = await paired.json();
        const headers = {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'};
        const submitted = await fetch('/api/v1/investigations', {
            method: 'POST', headers,
            body: JSON.stringify({idempotency_key: 'c'.repeat(32), incident})
        });
        const job = await submitted.json();
        const path = `/api/v1/investigations/${job.id}`;
        const progress = await (await fetch(path + '/events', {headers})).text();
        const report = await (await fetch(path + '/report', {headers})).json();
        const exported = await fetch(path + '/report/export', {headers});
        const exportReport = await exported.json();
        const recalled = await fetch(path + '/report/recall', {
            method: 'POST', headers, body: JSON.stringify({reason: 'security_review'})
        });
        const denied = await fetch(path + '/report/export', {headers});
        await fetch('/api/v1/session', {method: 'DELETE', headers});
        const revoked = await fetch(path, {headers});
        return {
            accepted: submitted.status, completed: progress.includes('"status":"succeeded"'),
            status: report.status, pinned: report.pin.candidate_digest === job.pin.candidate_digest,
            sameExport: JSON.stringify(report) === JSON.stringify(exportReport),
            attachment: exported.headers.get('Content-Disposition'),
            recalled: recalled.status, denied: denied.status, revoked: revoked.status,
            saved: [localStorage.length, sessionStorage.length],
            leaked: progress.includes(token) || progress.includes(secret)
        };
    }""",
        {"secret": sessions.issue_pairing(), "incident": source},
    )
    assert result["accepted"] == 202 and result["completed"]
    assert result["status"] == "resolved" and result["pinned"] and result["sameExport"]
    assert result["attachment"].startswith("attachment;")
    assert (result["recalled"], result["denied"], result["revoked"]) == (200, 409, 401)
    assert result["saved"] == [0, 0] and not result["leaked"]
    assert page.context.cookies() == []
