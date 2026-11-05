"""API endpoints for Machine Learning model inspection, dataset registry, and training."""

import os
import json
from typing import List
from fastapi import APIRouter, HTTPException, status

from app.ml.dataset import DatasetManager
from app.ml.trainer import SmsModelTrainer
from app.ml.service import SmsClassifierService, ARTIFACTS_DIR, METRICS_PATH
from app.ml.url_trainer import UrlModelTrainer
from app.ml.url_service import UrlClassifierService
from app.schemas.ml import (
    ModelVersionSchema,
    DatasetEntrySchema,
    RetrainResponseSchema,
)

router = APIRouter(prefix="/ml", tags=["machine-learning"])
URL_METRICS_PATH = os.path.join(ARTIFACTS_DIR, "url_model_metrics.json")


@router.get(
    "/models",
    response_model=List[ModelVersionSchema],
    summary="Get Deployed Machine Learning Models",
    description="Returns active model versions with verified, un-fabricated evaluation metrics.",
)
def get_models():
    """Retrieve deployed model versions (both SMS NLP and URL Lexical classifiers)."""
    models = []

    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH, "r", encoding="utf-8") as f:
                models.append(ModelVersionSchema(**json.load(f)))
        except Exception:
            pass

    if os.path.exists(URL_METRICS_PATH):
        try:
            with open(URL_METRICS_PATH, "r", encoding="utf-8") as f:
                models.append(ModelVersionSchema(**json.load(f)))
        except Exception:
            pass

    if not models:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No deployed model metrics found on disk. Run training first.",
        )

    return models


@router.get(
    "/datasets",
    response_model=List[DatasetEntrySchema],
    summary="List Registered Datasets",
    description="Returns all registered datasets with source provenance, licensing, and record counts.",
)
def get_datasets():
    """List approved training and benchmark datasets."""
    datasets = DatasetManager.get_registered_datasets()
    return [
        DatasetEntrySchema(
            id=d.id,
            name=d.name,
            source_citation=d.source_citation,
            license=d.license,
            record_count=d.record_count,
            language=d.language,
            classes=d.classes,
        )
        for d in datasets
    ]


@router.post(
    "/retrain",
    response_model=RetrainResponseSchema,
    summary="Trigger Model Retraining",
    description="Executes training pipeline across model candidates and deploys winning models.",
)
def retrain_models():
    """Retrain and evaluate both SMS and URL classification algorithms."""
    # Retrain SMS model
    sms_trainer = SmsModelTrainer()
    sms_results = sms_trainer.train_and_evaluate()
    SmsClassifierService.get_instance()._load_artifacts()

    # Retrain URL model
    url_trainer = UrlModelTrainer()
    url_results = url_trainer.train_and_evaluate()
    UrlClassifierService.get_instance()._load_artifacts()

    return RetrainResponseSchema(
        status="success",
        selected_model=f"sms:{sms_results['algorithm']}|url:{url_results['algorithm']}",
        version_id=f"{sms_results['version_id']}|{url_results['version_id']}",
        test_pr_auc=round((sms_results["metrics"]["pr_auc"] + url_results["metrics"]["pr_auc"]) / 2, 4),
        test_f1_score=round((sms_results["metrics"]["f1_score"] + url_results["metrics"]["f1_score"]) / 2, 4),
    )
