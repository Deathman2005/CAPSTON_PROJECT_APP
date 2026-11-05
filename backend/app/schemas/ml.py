"""Pydantic schemas for Machine Learning models and dataset registry."""

from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ModelMetricsSchema(BaseModel):
    """Real evaluation metrics computed on held-out test split."""

    precision: float
    recall: float
    f1_score: float
    accuracy: float
    roc_auc: float
    pr_auc: float
    confusion_matrix: List[List[int]]


class ModelVersionSchema(BaseModel):
    """Detailed model registry entry."""

    version_id: str
    algorithm: str
    deployed_at: str
    metrics: ModelMetricsSchema
    dataset_records: int
    train_size: int
    test_size: int
    all_candidates: Dict[str, Any] = Field(default_factory=dict)


class DatasetEntrySchema(BaseModel):
    """Dataset registry provenance entry."""

    id: str
    name: str
    source_citation: str
    license: str
    record_count: int
    language: str
    classes: List[str]


class RetrainResponseSchema(BaseModel):
    """Response returned upon retraining pipeline execution."""

    status: str
    selected_model: str
    version_id: str
    test_pr_auc: float
    test_f1_score: float

