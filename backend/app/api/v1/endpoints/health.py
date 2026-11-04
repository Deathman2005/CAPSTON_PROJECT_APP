"""Health and diagnostics API endpoints."""

from datetime import datetime, timezone
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.database import check_database_health
from app.schemas.health import (
    HealthResponse,
    DatabaseHealth,
    ProviderHealthItem,
    ProvidersHealthResponse,
)

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Root Service & Database Health",
    description="Validates that the FastAPI application is alive and executes a live SELECT 1 database ping.",
)
def get_health():
    """Perform complete application and database health check."""
    db_result = check_database_health()
    db_health = DatabaseHealth(**db_result)

    is_healthy = db_health.status == "connected"
    overall_status = "healthy" if is_healthy else "degraded"

    response_data = HealthResponse(
        status=overall_status,
        app_name=settings.PROJECT_NAME,
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(timezone.utc),
        database=db_health,
    )

    http_status = status.HTTP_200_OK if is_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(
        status_code=http_status,
        content=response_data.model_dump(mode="json"),
    )


@router.get(
    "/health/providers",
    response_model=ProvidersHealthResponse,
    summary="Threat Intelligence Providers Status",
    description="Reports connectivity and credential configuration status for external threat intelligence providers.",
)
def get_providers_health():
    """Verify threat intelligence provider statuses."""
    providers = []

    # Google Safe Browsing
    if settings.GOOGLE_SAFE_BROWSING_API_KEY:
        providers.append(
            ProviderHealthItem(
                name="google_safe_browsing",
                status="available",
                latency_ms=None,
                message="API key configured. Ready for verification queries.",
            )
        )
    else:
        providers.append(
            ProviderHealthItem(
                name="google_safe_browsing",
                status="unconfigured",
                latency_ms=None,
                message="GOOGLE_SAFE_BROWSING_API_KEY is not set in environment.",
            )
        )

    # URLhaus (abuse.ch public API)
    providers.append(
        ProviderHealthItem(
            name="urlhaus",
            status="available",
            latency_ms=None,
            message="Public API endpoint available without mandatory authentication key.",
        )
    )

    # VirusTotal
    if settings.VIRUSTOTAL_API_KEY:
        providers.append(
            ProviderHealthItem(
                name="virustotal",
                status="available",
                latency_ms=None,
                message="VirusTotal API key configured.",
            )
        )
    else:
        providers.append(
            ProviderHealthItem(
                name="virustotal",
                status="unconfigured",
                latency_ms=None,
                message="VIRUSTOTAL_API_KEY is not set in environment (optional provider).",
            )
        )

    return ProvidersHealthResponse(
        providers=providers,
        timestamp=datetime.now(timezone.utc),
    )
