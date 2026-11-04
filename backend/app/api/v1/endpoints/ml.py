"""API endpoints for Machine Learning model inspection, dataset registry, and training."""

import os
import json
from typing import List
from fastapi import APIRouter, HTTPException, status

from app.ml.dataset import DatasetManager
from app.ml.trainer import SmsModelTrainer
from app.ml.service import SmsClassifierService, ARTIFACTS_DIR, METRICS_PATH
from app.schemas.ml import (
    ModelVersionSchema,
    DatasetEntrySchema,
    RetrainResponseSchema,
)

router = APIRouter(prefix="/ml", tags=["machine-learning"])


@router.get(
    "/models",
    response_model=List[ModelVersionSchema],
    summary="Get Deployed Machine Learning Models",
    description="Returns active and historical model versions with verified evaluation metrics.",
)
def get_models():
    """Retrieve deployed model versions and performance audits."""
    if not os.path.exists(METRICS_PATH):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No deployed model metrics found on disk. Run training first.",
        )

    with open(METRICS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    return [ModelVersionSchema(**data)]


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
    description="Executes training pipeline across model candidates and deploys winning model.",
)
def retrain_models():
    """Retrain and evaluate SMS classification algorithms."""
    trainer = SmsModelTrainer()
    results = trainer.train_and_evaluate()

    # Reload singleton service to pick up newly trained model artifact
    service = SmsClassifierService.get_instance()
    service._load_artifacts()

    return RetrainResponseSchema(
        status="success",
        selected_model=results["algorithm"],
        version_id=results["version_id"],
        test_pr_auc=results["metrics"]["pr_auc"],
        test_f1_score=results["metrics"]["f1_score"],
    )
