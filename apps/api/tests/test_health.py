from fastapi.testclient import TestClient
from incident_investigator.main import create_app


def test_liveness_returns_version() -> None:
    response = TestClient(create_app()).get("/api/v1/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "0.1.0"}
