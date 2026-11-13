"""API endpoint for QR code security inspection and UPI payment intent analysis."""

from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status

from app.schemas.qr import QrScanRequest, QrScanResponse
from app.services.upi.qr_decoder import QrDecoderService

router = APIRouter(prefix="/scan", tags=["qr-scanner"])
qr_service = QrDecoderService.get_instance()


@router.post(
    "/qr",
    response_model=QrScanResponse,
    summary="Scan and Analyze QR Code or UPI Intent",
    description="Inspects QR code payloads for UPI payment scams, payee VPA impersonation, deceptive credit lures, or embedded phishing URLs.",
)
async def scan_qr(request: QrScanRequest):
    """Evaluates QR code content string for financial payment scams and phishing."""
    content = request.qr_content.strip()
    if not content:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="QR code content cannot be empty.",
        )

    result = await qr_service.analyze_qr_content(content)

    return QrScanResponse(
        scan_id=result.scan_id,
        payload_type=result.payload_type.value,
        raw_content=result.raw_content,
        parsed_upi=result.parsed_upi,
        classification=result.classification,
        risk_score=result.risk_score,
        confidence=result.confidence,
        reasons=result.reasons,
        recommendation=result.recommendation,
        explanation=result.explanation,
        timestamp=datetime.now(timezone.utc),
    )

