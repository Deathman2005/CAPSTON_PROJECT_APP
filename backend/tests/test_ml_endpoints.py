"""Integration tests for Machine Learning inspection and retraining API endpoints."""

import pytest
from starlette.testclient import TestClient


def test_get_models_endpoint(client: TestClient):
    """Verify GET /api/v1/ml/models returns active model versions and evaluation metrics."""
    response = client.get("/api/v1/ml/models")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1

    model = data[0]
    assert "version_id" in model
    assert "algorithm" in model
    assert "metrics" in model
    assert "pr_auc" in model["metrics"]
    assert "precision" in model["metrics"]
    assert "recall" in model["metrics"]
    assert "f1_score" in model["metrics"]


def test_get_datasets_endpoint(client: TestClient):
    """Verify GET /api/v1/ml/datasets returns registry with licenses and citations."""
    response = client.get("/api/v1/ml/datasets")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 5

    ds1 = next(d for d in data if d["id"] == "DS-01")
    assert "SMS Shield" in ds1["name"]
    assert "CC BY" in ds1["license"]
    assert ds1["record_count"] > 0


def test_retrain_endpoint(client: TestClient):
    """Verify POST /api/v1/ml/retrain executes pipeline and returns updated model."""
    response = client.post("/api/v1/ml/retrain")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "selected_model" in data
    assert "version_id" in data
    assert data["test_pr_auc"] > 0.0

