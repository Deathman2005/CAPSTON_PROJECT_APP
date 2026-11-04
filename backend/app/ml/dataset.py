"""Dataset registry, loader, deduplication, and stratified partition manager."""

import os
import pandas as pd
from typing import Tuple, List, Optional
from pydantic import BaseModel
from sklearn.model_selection import train_test_split


class DatasetMetadata(BaseModel):
    """Metadata describing an approved training or evaluation dataset."""

    id: str
    name: str
    source_citation: str
    license: str
    record_count: int
    language: str
    classes: List[str]


APPROVED_DATASETS: List[DatasetMetadata] = [
    DatasetMetadata(
        id="DS-01",
        name="SMS Shield Curated Phishing and Spam Benchmark",
        source_citation="SMS Shield Security Research Initiative (2026)",
        license="CC BY 4.0",
        record_count=75,
        language="English / Hinglish",
        classes=["legitimate", "scam"],
    ),
    DatasetMetadata(
        id="DS-02",
        name="ISOT Fake and Scam SMS Corpus",
        source_citation="University of Victoria ISOT Laboratory",
        license="Academic / Research",
        record_count=12000,
        language="English",
        classes=["legitimate", "scam"],
    ),
    DatasetMetadata(
        id="DS-03",
        name="PhishTank Phishing URL Corpus",
        source_citation="PhishTank Community Feed (OpenDNS / Cisco)",
        license="Community Terms",
        record_count=30000,
        language="Global",
        classes=["phishing"],
    ),
    DatasetMetadata(
        id="DS-04",
        name="URLhaus Abuse Feed",
        source_citation="abuse.ch Malware and Phishing Research",
        license="CC0 (Public Domain)",
        record_count=50000,
        language="Global",
        classes=["malware", "phishing"],
    ),
    DatasetMetadata(
        id="DS-05",
        name="Majestic Million Benign Domains",
        source_citation="Majestic-12",
        license="Creative Commons",
        record_count=1000000,
        language="Global",
        classes=["benign"],
    ),
]


class DatasetManager:
    """Manages dataset retrieval, hygiene, deduplication, and stratified splitting."""

    @classmethod
    def get_registered_datasets(cls) -> List[DatasetMetadata]:
        return APPROVED_DATASETS

    @classmethod
    def get_dataset_metadata(cls, dataset_id: str) -> Optional[DatasetMetadata]:
        for d in APPROVED_DATASETS:
            if d.id == dataset_id:
                return d
        return None

    @classmethod
    def load_dataset(cls, csv_path: Optional[str] = None) -> pd.DataFrame:
        """
        Loads dataset from disk, enforces validation and deduplication standards.
        Deduplication is performed BEFORE splitting to strictly prevent data leakage.
        """
        if csv_path is None:
            csv_path = os.path.join(os.path.dirname(__file__), "data", "sms_corpus.csv")

        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"SMS dataset not found at: {csv_path}")

        df = pd.read_csv(csv_path, encoding="utf-8")

        # 1. Schema Validation
        required_cols = {"text", "label"}
        if not required_cols.issubset(df.columns):
            raise ValueError(f"Dataset missing required columns {required_cols}. Found: {df.columns.tolist()}")

        # 2. Cleanup & Normalization
        df = df.dropna(subset=["text", "label"]).copy()
        df["text"] = df["text"].astype(str).str.strip()
        df["label"] = df["label"].astype(int)

        # Drop empty strings
        df = df[df["text"].str.len() > 0].copy()

        # 3. Deduplication (Data Leakage Prevention)
        initial_count = len(df)
        df = df.drop_duplicates(subset=["text"]).copy()
        df = df.reset_index(drop=True)

        return df

    @classmethod
    def split_data(
        cls,
        df: pd.DataFrame,
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
        random_state: int = 42,
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Performs stratified 3-way partition (Train / Val / Test) while preserving
        exact class distributions.
        """
        assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-5, "Ratios must sum to 1.0"

        # First split off test set
        val_plus_test_ratio = val_ratio + test_ratio
        train_df, temp_df = train_test_split(
            df,
            test_size=val_plus_test_ratio,
            random_state=random_state,
            stratify=df["label"],
        )

        # Split remaining into validation and test sets
        relative_test_ratio = test_ratio / val_plus_test_ratio
        val_df, test_df = train_test_split(
            temp_df,
            test_size=relative_test_ratio,
            random_state=random_state,
            stratify=temp_df["label"],
        )

        return (
            train_df.reset_index(drop=True),
            val_df.reset_index(drop=True),
            test_df.reset_index(drop=True),
        )
