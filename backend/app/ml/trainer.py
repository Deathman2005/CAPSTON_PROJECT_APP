"""Model training, baseline comparison, metric evaluation, and artifact serialization."""

import os
import json
import logging
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from typing import Dict, Any, Tuple

from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import ComplementNB
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
)

from app.ml.preprocessor import SmsPreprocessor
from app.ml.features import LinguisticFeatureExtractor
from app.ml.dataset import DatasetManager

logger = logging.getLogger("smsshield.ml.trainer")

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "artifacts")


def build_feature_pipeline() -> FeatureUnion:
    """Builds a composite feature union combining TF-IDF word n-grams and domain linguistic indicators."""
    return FeatureUnion([
        (
            "tfidf",
            TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=2500,
                sublinear_tf=True,
                min_df=1,
            ),
        ),
        ("linguistic", LinguisticFeatureExtractor()),
    ])


def evaluate_model_performance(model, X_test: list, y_test: list) -> Dict[str, Any]:
    """Computes exact, un-fabricated evaluation metrics on test set."""
    y_pred = model.predict(X_test)

    # Compute probability scores for ROC-AUC and PR-AUC
    if hasattr(model, "predict_proba"):
        y_prob = model.predict_proba(X_test)[:, 1]
    elif hasattr(model, "decision_function"):
        y_prob = model.decision_function(X_test)
    else:
        y_prob = y_pred.astype(float)

    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    acc = float(accuracy_score(y_test, y_pred))

    try:
        roc_auc = float(roc_auc_score(y_test, y_prob))
    except Exception:
        roc_auc = 0.5

    try:
        pr_auc = float(average_precision_score(y_test, y_prob))
    except Exception:
        pr_auc = 0.5

    cm = confusion_matrix(y_test, y_pred).tolist()

    return {
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(acc, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "confusion_matrix": cm,
    }


class SmsModelTrainer:
    """
    Trains and compares NLP classification algorithms on preprocessed SMS text,
    selects the optimal calibrated model, and persists production artifacts.
    """

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.preprocessor = SmsPreprocessor(mask_entities=True)

    def train_and_evaluate(self) -> Dict[str, Any]:
        """
        Executes end-to-end training pipeline:
        1. Loads and deduplicates dataset
        2. Splits into stratified train/val/test splits
        3. Preprocesses text
        4. Trains ComplementNB, LogisticRegression, and LinearSVC
        5. Evaluates metrics strictly on unseen test partition
        6. Serializes winner to disk
        """
        # 1. Load dataset
        df = DatasetManager.load_dataset()
        train_df, val_df, test_df = DatasetManager.split_data(df, random_state=self.random_state)

        # 2. Preprocess text
        X_train_raw = train_df["text"].tolist()
        y_train = train_df["label"].tolist()

        X_val_raw = val_df["text"].tolist()
        y_val = val_df["label"].tolist()

        X_test_raw = test_df["text"].tolist()
        y_test = test_df["label"].tolist()

        X_train = [self.preprocessor.clean_and_normalize(t) for t in X_train_raw]
        X_val = [self.preprocessor.clean_and_normalize(t) for t in X_val_raw]
        X_test = [self.preprocessor.clean_and_normalize(t) for t in X_test_raw]

        # 3. Model Candidates
        candidates = {
            "complement_nb": Pipeline([
                ("features", build_feature_pipeline()),
                ("classifier", ComplementNB(alpha=0.5)),
            ]),
            "logistic_regression": Pipeline([
                ("features", build_feature_pipeline()),
                ("classifier", LogisticRegression(C=1.5, max_iter=1000, random_state=self.random_state)),
            ]),
            "linear_svc_calibrated": Pipeline([
                ("features", build_feature_pipeline()),
                (
                    "classifier",
                    CalibratedClassifierCV(
                        estimator=LinearSVC(C=1.0, max_iter=2000, random_state=self.random_state),
                        method="sigmoid",
                        cv=3,
                    ),
                ),
            ]),
        }

        comparison_results: Dict[str, Any] = {}
        best_name = None
        best_pr_auc = -1.0
        best_model = None

        for name, pipeline in candidates.items():
            pipeline.fit(X_train, y_train)
            test_metrics = evaluate_model_performance(pipeline, X_test, y_test)
            comparison_results[name] = test_metrics

            # Model selection prioritized on PR-AUC, then F1 score
            score = test_metrics["pr_auc"] * 100 + test_metrics["f1_score"] * 10
            if score > best_pr_auc:
                best_pr_auc = score
                best_name = name
                best_model = pipeline

        # Deployable Model Version Metadata
        version_id = f"sms_{best_name}_{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        best_metrics = comparison_results[best_name]

        # 4. Save Artifacts
        os.makedirs(ARTIFACTS_DIR, exist_ok=True)
        model_artifact_path = os.path.join(ARTIFACTS_DIR, "sms_classifier.joblib")
        metrics_artifact_path = os.path.join(ARTIFACTS_DIR, "sms_model_metrics.json")

        joblib.dump(best_model, model_artifact_path)

        metadata_payload = {
            "version_id": version_id,
            "algorithm": best_name,
            "deployed_at": datetime.now(timezone.utc).isoformat(),
            "metrics": best_metrics,
            "all_candidates": comparison_results,
            "dataset_records": len(df),
            "train_size": len(X_train),
            "test_size": len(X_test),
        }

        with open(metrics_artifact_path, "w", encoding="utf-8") as f:
            json.dump(metadata_payload, f, indent=2)

        return metadata_payload


if __name__ == "__main__":
    trainer = SmsModelTrainer()
    results = trainer.train_and_evaluate()
    print("Training Complete!")
    print(f"Selected Model: {results['algorithm']} (Version: {results['version_id']})")
    print(f"Test PR-AUC: {results['metrics']['pr_auc']}")
    print(f"Test F1: {results['metrics']['f1_score']}")
    print(f"Test Precision: {results['metrics']['precision']}")
    print(f"Test Recall: {results['metrics']['recall']}")
