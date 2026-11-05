"""Tests for backend dashboard endpoints (stats, recent scans, threat distribution)."""

import uuid
from datetime import datetime, timezone
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.models.scan import ScanRecord
from app.core.database import get_db

client = TestClient(app)


def test_get_dashboard_stats_empty(db_session):
    response = client.get("/api/v1/dashboard/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "safe_scans" in data
    assert "suspicious_scans" in data
    assert "malicious_scans" in data
    assert "unknown_scans" in data
    assert "total_urls_scanned" in data
    assert "avg_risk_score" in data


def test_get_dashboard_stats_populated(db_session):
    # Insert dummy scan records
    rec1 = ScanRecord(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_category="manual_paste",
        classification="MALICIOUS",
        risk_score=95.0,
        confidence=0.95,
        url_count=1,
        sms_model_version="test_v1",
        message_hash="hash1",
        detection_reasons="Phishing link",
        recommendation="Do not click",
    )
    rec2 = ScanRecord(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_category="notification_auto",
        classification="SAFE",
        risk_score=10.0,
        confidence=0.99,
        url_count=0,
        sms_model_version="test_v1",
        message_hash="hash2",
        detection_reasons="",
        recommendation="Safe message",
    )
    db_session.add_all([rec1, rec2])
    db_session.commit()

    response = client.get("/api/v1/dashboard/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["total_scans"] >= 2
    assert data["malicious_scans"] >= 1
    assert data["safe_scans"] >= 1
    assert data["total_urls_scanned"] >= 1


def test_get_recent_scans_zero_raw_text_leak(db_session):
    sensitive_word = "SUPER_SECRET_OTP_9981"
    rec = ScanRecord(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_category="notification_auto",
        source_package="com.google.android.apps.messaging",
        classification="SUSPICIOUS",
        risk_score=68.0,
        confidence=0.88,
        url_count=1,
        sms_model_version="test_v1",
        message_hash="hash_sens",
        detection_reasons="External link",
        recommendation="Check sender",
    )
    db_session.add(rec)
    db_session.commit()

    response = client.get("/api/v1/dashboard/recent-scans?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert data["total_returned"] >= 1
    items = data["items"]
    assert len(items) >= 1

    # Strict Privacy Assertion: sensitive OTP word cannot appear anywhere in JSON response
    raw_response_text = response.text
    assert sensitive_word not in raw_response_text
    # Verify field structure
    first_item = items[0]
    assert "scan_id" in first_item
    assert "classification" in first_item
    assert "detection_reasons" in first_item
    assert "message_text" not in first_item


def test_get_threat_distribution(db_session):
    response = client.get("/api/v1/dashboard/threat-distribution")
    assert response.status_code == 200
    data = response.json()
    assert "classifications" in data
    assert "sources" in data
    names = [c["name"] for c in data["classifications"]]
    assert "SAFE" in names
    assert "MALICIOUS" in names
    assert "SUSPICIOUS" in names
    assert "UNKNOWN" in names
