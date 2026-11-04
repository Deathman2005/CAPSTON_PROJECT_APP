"""Unit tests for dataset registry, loader, deduplication, and stratified partition."""

import pytest
import pandas as pd
from app.ml.dataset import DatasetManager, APPROVED_DATASETS


def test_registered_datasets_metadata():
    """Verify registry exposes approved datasets with required licensing and provenance."""
    datasets = DatasetManager.get_registered_datasets()
    assert len(datasets) >= 5
    ids = [d.id for d in datasets]
    assert "DS-01" in ids
    assert "DS-02" in ids
    assert "DS-03" in ids
    assert "DS-04" in ids
    assert "DS-05" in ids

    ds1 = DatasetManager.get_dataset_metadata("DS-01")
    assert ds1 is not None
    assert "CC BY" in ds1.license
    assert ds1.record_count > 0


def test_load_dataset_deduplication():
    """Verify loading cleans text and removes duplicate entries to prevent data leakage."""
    df = DatasetManager.load_dataset()
    assert isinstance(df, pd.DataFrame)
    assert len(df) > 0
    assert "text" in df.columns
    assert "label" in df.columns

    # Verify no duplicates exist in text column
    assert df["text"].duplicated().sum() == 0


def test_stratified_split_preserves_class_balance_and_disjoint():
    """Verify train, val, and test partitions preserve balance and do not overlap."""
    df = DatasetManager.load_dataset()
    train_df, val_df, test_df = DatasetManager.split_data(
        df, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, random_state=42
    )

    total_len = len(df)
    assert len(train_df) + len(val_df) + len(test_df) == total_len

    # Verify partitions are disjoint
    train_texts = set(train_df["text"])
    val_texts = set(val_df["text"])
    test_texts = set(test_df["text"])

    assert len(train_texts.intersection(val_texts)) == 0
    assert len(train_texts.intersection(test_texts)) == 0
    assert len(val_texts.intersection(test_texts)) == 0

    # Verify both classes exist in all splits
    for partition in [train_df, val_df, test_df]:
        assert 0 in partition["label"].values
        assert 1 in partition["label"].values
