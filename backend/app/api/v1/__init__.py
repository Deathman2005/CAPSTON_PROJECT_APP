"""API v1 router assembly."""

from fastapi import APIRouter
from app.api.v1.endpoints import health, scan_url, scan_message, ml

api_v1_router = APIRouter()
api_v1_router.include_router(health.router)
api_v1_router.include_router(scan_url.router)
api_v1_router.include_router(scan_message.router)
api_v1_router.include_router(ml.router)
