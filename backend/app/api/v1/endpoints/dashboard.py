"""API endpoints for dashboard analytics, threat distribution, and audit history."""

from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, desc
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.scan import ScanRecord
from app.schemas.dashboard import (
    DashboardStatsResponse,
    RecentScansResponse,
    RecentScanItem,
    ThreatDistributionResponse,
    ThreatDistributionCategory,
)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(db: Session = Depends(get_db)):
    """
    Returns aggregate statistics across all processed SMS and URL scans.
    NON-NEGOTIABLE PRIVACY: Strictly statistical aggregates; zero message content.
    """
    total_scans = db.scalar(select(func.count(ScanRecord.id))) or 0
    safe_scans = (
        db.scalar(
            select(func.count(ScanRecord.id)).where(
                func.upper(ScanRecord.classification) == "SAFE"
            )
        )
        or 0
    )
    suspicious_scans = (
        db.scalar(
            select(func.count(ScanRecord.id)).where(
                func.upper(ScanRecord.classification) == "SUSPICIOUS"
            )
        )
        or 0
    )
    malicious_scans = (
        db.scalar(
            select(func.count(ScanRecord.id)).where(
                func.upper(ScanRecord.classification) == "MALICIOUS"
            )
        )
        or 0
    )
    unknown_scans = (
        db.scalar(
            select(func.count(ScanRecord.id)).where(
                func.upper(ScanRecord.classification) == "UNKNOWN"
            )
        )
        or 0
    )
    total_urls = db.scalar(select(func.coalesce(func.sum(ScanRecord.url_count), 0))) or 0
    avg_score = (
        db.scalar(
            select(func.coalesce(func.avg(ScanRecord.risk_score), 0.0)).where(
                ScanRecord.risk_score.isnot(None)
            )
        )
        or 0.0
    )

    return DashboardStatsResponse(
        total_scans=total_scans,
        safe_scans=safe_scans,
        suspicious_scans=suspicious_scans,
        malicious_scans=malicious_scans,
        unknown_scans=unknown_scans,
        total_urls_scanned=int(total_urls),
        avg_risk_score=round(float(avg_score), 1),
        timestamp=datetime.now(timezone.utc),
    )


@router.get("/recent-scans", response_model=RecentScansResponse)
def get_recent_scans(
    limit: int = Query(default=20, ge=1, le=100, description="Max audit entries to retrieve"),
    db: Session = Depends(get_db),
):
    """
    Retrieves latest scan inquiries for audit tracking.
    NON-NEGOTIABLE PRIVACY: Returns only classification, score, and indicators; zero raw SMS text.
    """
    records = db.scalars(
        select(ScanRecord).order_by(desc(ScanRecord.timestamp)).limit(limit)
    ).all()

    items: List[RecentScanItem] = []
    for rec in records:
        reasons_list = [
            r.strip() for r in (rec.detection_reasons or "").split("||") if r.strip()
        ]
        items.append(
            RecentScanItem(
                scan_id=rec.id,
                timestamp=rec.timestamp,
                source_category=rec.source_category,
                source_package=rec.source_package,
                classification=rec.classification.upper(),
                risk_score=rec.risk_score,
                confidence=rec.confidence,
                url_count=rec.url_count,
                detection_reasons=reasons_list,
                recommendation=rec.recommendation,
            )
        )

    return RecentScansResponse(total_returned=len(items), items=items)


@router.get("/threat-distribution", response_model=ThreatDistributionResponse)
def get_threat_distribution(db: Session = Depends(get_db)):
    """
    Returns breakdown of scans by security classification and source channels for charting.
    """
    total_scans = db.scalar(select(func.count(ScanRecord.id))) or 0

    # 1. Classification distribution
    class_counts = {
        "SAFE": 0,
        "SUSPICIOUS": 0,
        "MALICIOUS": 0,
        "UNKNOWN": 0,
    }
    class_rows = db.execute(
        select(func.upper(ScanRecord.classification), func.count(ScanRecord.id)).group_by(
            func.upper(ScanRecord.classification)
        )
    ).all()

    for name, count in class_rows:
        if name in class_counts:
            class_counts[name] = count

    class_categories = [
        ThreatDistributionCategory(
            name=k,
            count=v,
            percentage=round((v / total_scans * 100.0), 1) if total_scans > 0 else 0.0,
        )
        for k, v in class_counts.items()
    ]

    # 2. Source channel distribution
    source_rows = db.execute(
        select(ScanRecord.source_category, func.count(ScanRecord.id)).group_by(
            ScanRecord.source_category
        )
    ).all()

    source_categories = [
        ThreatDistributionCategory(
            name=name,
            count=count,
            percentage=round((count / total_scans * 100.0), 1) if total_scans > 0 else 0.0,
        )
        for name, count in source_rows
    ]

    return ThreatDistributionResponse(
        classifications=class_categories,
        sources=source_categories,
        timestamp=datetime.now(timezone.utc),
    )

