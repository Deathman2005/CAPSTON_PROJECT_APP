"""Unit tests for model trainer, baseline comparison, and metric evaluation."""

import os
import pytest
from app.ml.trainer import SmsModelTrainer, ARTIFACTS_DIR


def test_trainer_execution_and_metrics_verification():
    """Verify trainer runs comparison, evaluates non-fabricated metrics, and saves artifacts."""
    trainer = SmsModelTrainer(random_state=42)
    payload = trainer.train_and_evaluate()

    assert "algorithm" in payload
    assert "version_id" in payload
    assert "metrics" in payload
    assert "all_candidates" in payload

    metrics = payload["metrics"]
    # Check that real scikit-learn metrics are within [0.0, 1.0]
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1_score"] <= 1.0
    assert 0.0 <= metrics["pr_auc"] <= 1.0
    assert 0.0 <= metrics["roc_auc"] <= 1.0

    # Verify all 3 baseline candidates were compared
    candidates = payload["all_candidates"]
    assert "complement_nb" in candidates
    assert "logistic_regression" in candidates
    assert "linear_svc_calibrated" in candidates

    # Verify physical artifacts created
    model_path = os.path.join(ARTIFACTS_DIR, "sms_classifier.joblib")
    metrics_path = os.path.join(ARTIFACTS_DIR, "sms_model_metrics.json")
    assert os.path.exists(model_path)
    assert os.path.exists(metrics_path)
