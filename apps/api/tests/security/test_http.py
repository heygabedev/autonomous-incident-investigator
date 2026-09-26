from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from incident_investigator.main import create_app
from incident_investigator.security.http import RuntimeSettings
from incident_investigator.security.sessions import Sessions
from pydantic import ValidationError


def client(sessions: Sessions | None = None, *, dev: bool = False) -> TestClient:
    return TestClient(
        create_app(RuntimeSettings(development=dev), sessions), base_url="http://127.0.0.1:8000"
    )


def test_pair_session_and_logout() -> None:
    sessions = Sessions()
    browser = client(sessions)
    secret = sessions.issue_pairing()
    response = browser.post("/api/v1/session", json={"secret": secret})
    assert response.status_code == 200
    assert "set-cookie" not in response.headers
    token = response.json()["token"]
    auth = {"Authorization": f"Bearer {token}"}
    assert browser.get("/api/v1/session", headers=auth).status_code == 200
    assert browser.delete("/api/v1/session", headers=auth).status_code == 200
    assert browser.get("/api/v1/session", headers=auth).status_code == 401
    assert browser.post("/api/v1/session", json={"secret": secret}).status_code == 401


@pytest.mark.parametrize("path", ["/api/v1/session", "/api/v1/evidence", "/docs", "/openapi.json"])
def test_routes_are_protected_by_default(path: str) -> None:
    assert client().get(path).status_code == 401


@pytest.mark.parametrize(
    "header,value,status",
    [
        ("Host", "evil.example", 400),
        ("Origin", "https://evil.example", 403),
        ("Origin", "null", 403),
        ("Sec-Fetch-Site", "cross-site", 403),
        ("X-Forwarded-For", "127.0.0.1", 400),
        ("Forwarded", "host=localhost", 400),
    ],
)
def test_hostile_headers(header: str, value: str, status: int) -> None:
    response = client().get("/api/v1/health/live", headers={header: value})
    assert response.status_code == status
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"


def test_development_origin_is_explicit() -> None:
    headers = {"Origin": "http://127.0.0.1:5173"}
    assert client().get("/api/v1/health/live", headers=headers).status_code == 403
    response = client(dev=True).options("/api/v1/session", headers=headers)
    assert response.headers["access-control-allow-origin"] == headers["Origin"]
    assert "access-control-allow-credentials" not in response.headers


@pytest.mark.parametrize("body", ['{"secret":"a","secret":"b"}', '{"secret":"sensitive"}', "null"])
def test_invalid_json_and_validation_never_echo_input(body: str) -> None:
    response = client().post(
        "/api/v1/session", content=body, headers={"Content-Type": "application/json"}
    )
    assert response.status_code in (400, 422)
    assert "sensitive" not in response.text


def test_body_limits_and_token_urls() -> None:
    browser = client()
    assert browser.post("/api/v1/session", content=b"x" * 1_048_577).status_code == 413
    response = browser.post("/api/v1/session", content=iter([b"x" * 600_000, b"y" * 600_000]))
    assert response.status_code == 413
    assert browser.get("/api/v1/health/live?token=secret").status_code == 400
    assert browser.post("/api/v1/session", content="text").status_code == 415
    assert browser.post("/api/v1/session", headers={"Content-Encoding": "gzip"}).status_code == 415


def test_reject_live_and_external_binding() -> None:
    with pytest.raises(ValidationError):
        RuntimeSettings(api_host="0.0.0.0")
    with pytest.raises(ValidationError):
        RuntimeSettings(app_mode="live")


def test_serves_built_ui_from_same_origin(tmp_path: Path) -> None:
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<h1>Console</h1>", encoding="utf-8")
    browser = TestClient(create_app(ui_directory=tmp_path), base_url="http://127.0.0.1:8000")
    response = browser.get("/")
    assert response.status_code == 200
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_future_handler_errors_are_generic() -> None:
    sessions = Sessions()
    app = create_app(sessions=sessions)

    @app.get("/future")
    def fail() -> None:
        raise RuntimeError("private-incident-secret")

    token = sessions.redeem(sessions.issue_pairing())
    response = TestClient(app, base_url="http://127.0.0.1:8000").get(
        "/future", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 500
    assert "private-incident-secret" not in response.text


@pytest.mark.parametrize("body", [b"\xff", b'{"secret":NaN}', b"\xff\xfe{\x00}", b"[]" * 100])
def test_malformed_encodings_and_numbers_are_rejected(body: bytes) -> None:
    assert (
        client()
        .post("/api/v1/session", content=body, headers={"Content-Type": "application/json"})
        .status_code
        == 400
    )


def test_duplicate_headers_and_smuggling_denied() -> None:
    for headers in (
        [("Host", "127.0.0.1:8000"), ("Host", "evil.invalid")],
        [("Origin", "http://127.0.0.1:8000"), ("Origin", "null")],
        [("Content-Length", "0"), ("Transfer-Encoding", "chunked")],
    ):
        assert client().post("/api/v1/session", headers=headers).status_code == 400


def test_retry_after_and_private_eval_not_exposed() -> None:
    browser = client()
    for _ in range(5):
        assert browser.post("/api/v1/session", json={"secret": "x" * 43}).status_code == 401
    response = browser.post("/api/v1/session", json={"secret": "x" * 43})
    assert response.status_code == 429 and int(response.headers["retry-after"]) > 0
    sessions = Sessions()
    token = sessions.redeem(sessions.issue_pairing())
    browser = client(sessions)
    for path in ("/api/v1/evaluation", "/api/v1/gold-labels", "/openapi.json", "/docs", "/redoc"):
        assert browser.get(path, headers={"Authorization": f"Bearer {token}"}).status_code == 404


def test_health_survives_audit_failure() -> None:
    def fail(*args: object) -> None:
        raise OSError("disk full and private secret")

    sessions = Sessions()
    secret = sessions.issue_pairing()
    sessions.audit = fail
    browser = client(sessions)
    response = browser.post("/api/v1/session", json={"secret": secret})
    assert response.status_code == 503
    assert "private secret" not in response.text
    assert browser.get("/api/v1/health/live").status_code == 200
