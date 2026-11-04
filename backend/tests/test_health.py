"""Unit and integration tests for service health endpoints."""

from starlette.testclient import TestClient


def test_root_endpoint(client: TestClient):
    """Verify the root welcome endpoint returns service identification."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "service" in data
    assert "version" in data
    assert data["docs_url"] == "/docs"


def test_root_health_endpoint(client: TestClient):
    """Verify that GET /health executes live database ping and reports healthy."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app_name"] == "SMS Shield AI Backend"
    assert "database" in data
    assert data["database"]["status"] == "connected"
    assert data["database"]["latency_ms"] is not None
    assert data["database"]["latency_ms"] >= 0.0


def test_api_v1_health_endpoint(client: TestClient):
    """Verify that versioned GET /api/v1/health also returns healthy status."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"]["status"] == "connected"


def test_threat_providers_health(client: TestClient):
    """Verify that GET /api/v1/health/providers reports provider configuration statuses."""
    response = client.get("/api/v1/health/providers")
    assert response.status_code == 200
    data = response.json()
    assert "providers" in data
    assert len(data["providers"]) >= 2

    provider_names = [p["name"] for p in data["providers"]]
    assert "google_safe_browsing" in provider_names
    assert "urlhaus" in provider_names

    # Check that URLhaus is available by default (free feed)
    urlhaus_item = next(p for p in data["providers"] if p["name"] == "urlhaus")
    assert urlhaus_item["status"] == "available"
