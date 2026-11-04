"""SMS Shield FastAPI Application Entrypoint."""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import check_database_health, engine
from app.api.router import api_router
from app.api.v1.endpoints.health import get_health

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("smsshield.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown procedures."""
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION} [{settings.ENVIRONMENT}]")
    db_status = check_database_health()
    if db_status["status"] == "connected":
        logger.info(f"Database connection verified: {db_status['dialect']} (ping: {db_status['latency_ms']}ms)")
    else:
        logger.warning(f"Database connection degraded at startup: {db_status.get('error')}")

    yield

    logger.info("Shutting down SMS Shield AI Backend...")
    engine.dispose()
    logger.info("Database connection engine disposed.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Privacy-preserving AI backend for SMS scam detection and malicious URL inspection.",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Root-level health endpoint (direct for container orchestration)
app.add_api_route("/health", get_health, methods=["GET"], tags=["health"])

# Include versioned API router
app.include_router(api_router)


@app.get("/", tags=["root"])
def root():
    """Welcome endpoint returning API service identification."""
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "docs_url": "/docs",
        "health_url": "/health",
    }
