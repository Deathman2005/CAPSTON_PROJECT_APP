"""Unit tests for URL model training, metric evaluation, and artifact creation."""

import os
import pytest
from app.ml.url_trainer import UrlModelTrainer, ARTIFACTS_DIR


def test_url_model_trainer_execution():
    """Verify URL trainer compares candidates, computes metrics, and saves artifact."""
    trainer = UrlModelTrainer(random_state=42)
    results = trainer.train_and_evaluate()

    assert "algorithm" in results
    assert "version_id" in results
    assert "metrics" in results
    assert "all_candidates" in results

    metrics = results["metrics"]
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1_score"] <= 1.0
    assert 0.0 <= metrics["pr_auc"] <= 1.0
    assert 0.0 <= metrics["roc_auc"] <= 1.0

    candidates = results["all_candidates"]
    assert "logistic_regression" in candidates
    assert "random_forest" in candidates
    assert "hist_gradient_boosting" in candidates

    model_path = os.path.join(ARTIFACTS_DIR, "url_classifier.joblib")
    metrics_path = os.path.join(ARTIFACTS_DIR, "url_model_metrics.json")
    assert os.path.exists(model_path)
    assert os.path.exists(metrics_path)
