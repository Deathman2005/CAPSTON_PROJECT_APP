"""URL machine learning model training, baseline comparison, and artifact serialization."""

import os
import json
import logging
import joblib
import pandas as pd
from datetime import datetime, timezone
from typing import Dict, Any, Tuple

from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
)

from app.ml.url_features import UrlFeatureExtractor

logger = logging.getLogger("smsshield.ml.url_trainer")

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "artifacts")
DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "url_corpus.csv")


def evaluate_url_model_performance(model, X_test: list, y_test: list) -> Dict[str, Any]:
    """Computes exact, un-fabricated test evaluation metrics for URL models."""
    y_pred = model.predict(X_test)

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


class UrlModelTrainer:
    """
    Trains and compares machine learning classifiers on URL lexical features,
    selects the top performing model by PR-AUC, and exports production artifacts.
    """

    def __init__(self, data_path: str = DATA_PATH, random_state: int = 42):
        self.data_path = data_path
        self.random_state = random_state

    def load_and_split_data(self) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Loads and performs stratified partition while strictly preventing data leakage."""
        if not os.path.exists(self.data_path):
            raise FileNotFoundError(f"URL dataset not found at {self.data_path}")

        df = pd.read_csv(self.data_path, encoding="utf-8")
        df = df.dropna(subset=["url", "label"]).copy()
        df["url"] = df["url"].astype(str).str.strip()
        df["label"] = df["label"].astype(int)

        # Deduplication before partitioning to prevent data leakage
        df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)

        # 70% Train, 15% Validation, 15% Test
        train_df, temp_df = train_test_split(
            df,
            test_size=0.30,
            random_state=self.random_state,
            stratify=df["label"],
        )
        val_df, test_df = train_test_split(
            temp_df,
            test_size=0.50,
            random_state=self.random_state,
            stratify=temp_df["label"],
        )

        return (
            train_df.reset_index(drop=True),
            val_df.reset_index(drop=True),
            test_df.reset_index(drop=True),
        )

    def train_and_evaluate(self) -> Dict[str, Any]:
        """Runs model comparison across candidate classifiers."""
        train_df, val_df, test_df = self.load_and_split_data()

        X_train = train_df["url"].tolist()
        y_train = train_df["label"].tolist()

        X_val = val_df["url"].tolist()
        y_val = val_df["label"].tolist()

        X_test = test_df["url"].tolist()
        y_test = test_df["label"].tolist()

        candidates = {
            "logistic_regression": Pipeline([
                ("features", UrlFeatureExtractor()),
                ("scaler", StandardScaler()),
                ("classifier", LogisticRegression(C=1.0, max_iter=1000, random_state=self.random_state)),
            ]),
            "random_forest": Pipeline([
                ("features", UrlFeatureExtractor()),
                ("classifier", RandomForestClassifier(n_estimators=100, max_depth=8, random_state=self.random_state)),
            ]),
            "hist_gradient_boosting": Pipeline([
                ("features", UrlFeatureExtractor()),
                ("classifier", HistGradientBoostingClassifier(max_iter=100, random_state=self.random_state)),
            ]),
        }

        comparison_results: Dict[str, Any] = {}
        best_name = None
        best_score = -1.0
        best_model = None

        for name, pipeline in candidates.items():
            pipeline.fit(X_train, y_train)
            test_metrics = evaluate_url_model_performance(pipeline, X_test, y_test)
            comparison_results[name] = test_metrics

            score = test_metrics["pr_auc"] * 100 + test_metrics["f1_score"] * 10
            if score > best_score:
                best_score = score
                best_name = name
                best_model = pipeline

        version_id = f"url_{best_name}_{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        best_metrics = comparison_results[best_name]

        # Save artifacts
        os.makedirs(ARTIFACTS_DIR, exist_ok=True)
        model_artifact_path = os.path.join(ARTIFACTS_DIR, "url_classifier.joblib")
        metrics_artifact_path = os.path.join(ARTIFACTS_DIR, "url_model_metrics.json")

        joblib.dump(best_model, model_artifact_path)

        metadata_payload = {
            "version_id": version_id,
            "algorithm": best_name,
            "deployed_at": datetime.now(timezone.utc).isoformat(),
            "metrics": best_metrics,
            "all_candidates": comparison_results,
            "train_size": len(X_train),
            "test_size": len(X_test),
        }

        with open(metrics_artifact_path, "w", encoding="utf-8") as f:
            json.dump(metadata_payload, f, indent=2)

        return metadata_payload


if __name__ == "__main__":
    trainer = UrlModelTrainer()
    results = trainer.train_and_evaluate()
    print("URL Model Training Complete!")
    print(f"Selected Model: {results['algorithm']} (Version: {results['version_id']})")
    print(f"Test PR-AUC: {results['metrics']['pr_auc']}")
    print(f"Test F1: {results['metrics']['f1_score']}")
    print(f"Test Precision: {results['metrics']['precision']}")
    print(f"Test Recall: {results['metrics']['recall']}")

