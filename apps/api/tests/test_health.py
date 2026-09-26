from fastapi.testclient import TestClient
from incident_investigator.main import create_app


def test_liveness_returns_minimal_status() -> None:
    response = TestClient(create_app(), base_url="http://127.0.0.1:8000").get("/api/v1/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
