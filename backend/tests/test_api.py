from fastapi.testclient import TestClient

from aegentra.api import app, create_app


def test_liveness_is_minimal() -> None:
    response = TestClient(app).get("/v1/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "live", "mode": "shadow"}


def test_unauthed_preview_not_exposed_in_default_app() -> None:
    response = TestClient(app).post("/v1/local/validate-manifest", json={"parts": []})
    assert response.status_code == 404


def test_local_validation_is_explicit_and_not_a_release_approval() -> None:
    payload = {"parts": [{"path": "main.js", "byte_length": 7, "sha256": "a" * 64}]}
    response = TestClient(create_app(enable_local_shadow_preview=True)).post(
        "/v1/local/validate-manifest", json=payload
    )
    assert response.status_code == 200
    assert response.json()["status"] == "VALID_METADATA_ONLY"
    assert len(response.json()["shadow_fingerprint"]) == 64
