"""SQLAlchemy 2.0 ORM models for scan records, URLs, and threat intelligence audits."""

import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import (
    String,
    Text,
    Float,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDPrimaryKeyMixin, TimestampMixin


class ScanRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Primary audit log for incoming scan inquiries.
    NON-NEGOTIABLE PRIVACY ENFORCEMENT: Raw message text is NEVER stored.
    """

    __tablename__ = "scan_records"

    # Ingestion timestamp
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False,
    )

    # Ingestion origin: 'notification_auto', 'manual_paste', 'manual_share'
    source_category: Mapped[str] = mapped_column(String(64), nullable=False)

    # Android package name (e.g. 'com.google.android.apps.messaging')
    source_package: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # Overall classification: 'SAFE', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN'
    classification: Mapped[str] = mapped_column(String(32), index=True, nullable=False)

    # Calibrated risk score: 0.0 to 100.0 (None if insufficient evidence)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Overall confidence score: 0.0 to 1.0
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Number of extracted URLs
    url_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Machine learning model identifier
    sms_model_version: Mapped[str] = mapped_column(String(64), nullable=False, default="baseline_heuristic_v1")

    # Cryptographic SHA-256 fingerprint of message for duplicate suppression (never raw text!)
    message_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)

    # Security indicators / triggered reasons (stored as delimited string)
    detection_reasons: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Recommendation presented to the user
    recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Associated URL scan records
    url_scans: Mapped[List["UrlScanResult"]] = relationship(
        "UrlScanResult",
        back_populates="scan_record",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class UrlScanResult(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Detailed inspection record for individual URLs.
    Stores normalized URLs with sensitive tracking parameters redacted.
    """

    __tablename__ = "url_scan_results"

    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scan_records.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Normalized URL (with tokens/auth query parameters redacted)
    normalized_url: Mapped[str] = mapped_column(Text, nullable=False)

    # Hostname or IP address
    domain: Mapped[str] = mapped_column(String(255), index=True, nullable=False)

    # Indicators
    is_ip_address: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_shortened: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_punycode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # URL Classification: 'benign', 'phishing', 'malware', 'suspicious', 'unknown'
    classification: Mapped[str] = mapped_column(String(32), index=True, nullable=False)

    # ML Feature classifier risk score: 0.0 to 100.0
    feature_risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Overall reputation verdict from threat intelligence providers
    reputation_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")

    # Relationship to parent scan record
    scan_record: Mapped[Optional["ScanRecord"]] = relationship(
        "ScanRecord",
        back_populates="url_scans",
    )

    # Associated threat intelligence provider responses
    provider_results: Mapped[List["ThreatProviderResult"]] = relationship(
        "ThreatProviderResult",
        back_populates="url_scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class ThreatProviderResult(Base, UUIDPrimaryKeyMixin):
    """
    Audit log of upstream threat intelligence provider query results.
    """

    __tablename__ = "threat_provider_results"

    url_scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("url_scan_results.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Provider name: 'google_safe_browsing', 'urlhaus', 'virustotal'
    provider_name: Mapped[str] = mapped_column(String(64), nullable=False)

    # Upstream status: 'clean', 'malicious', 'suspicious', 'unavailable', 'unknown'
    status: Mapped[str] = mapped_column(String(32), nullable=False)

    # Upstream latency in milliseconds
    latency_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Threat tags returned by provider (e.g. 'phishing', 'malware_download')
    threat_tags: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Reference or query identifier if provided
    reference_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # Timestamp of check
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    url_scan: Mapped["UrlScanResult"] = relationship(
        "UrlScanResult",
        back_populates="provider_results",
    )


class ModelVersion(Base):
    """
    Registry of deployed and versioned machine learning models.
    """

    __tablename__ = "model_versions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    model_type: Mapped[str] = mapped_column(String(32), nullable=False)  # 'sms_classifier' or 'url_classifier'
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    precision: Mapped[float] = mapped_column(Float, nullable=False)
    recall: Mapped[float] = mapped_column(Float, nullable=False)
    f1_score: Mapped[float] = mapped_column(Float, nullable=False)
    pr_auc: Mapped[float] = mapped_column(Float, nullable=False)
    deployed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class DatasetRegistryEntry(Base):
    """
    Registry of datasets used for training and model evaluation.
    """

    __tablename__ = "dataset_registry"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # e.g. 'DS-01'
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    source_url: Mapped[str] = mapped_column(String(255), nullable=False)
    license: Mapped[str] = mapped_column(String(64), nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False)
    language: Mapped[str] = mapped_column(String(32), nullable=False, default="English")
    classes: Mapped[str] = mapped_column(String(128), nullable=False)


class UserSetting(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    User-controlled privacy and retention settings.
    """

    __tablename__ = "user_settings"

    retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

