"""Pytest configuration and shared fixtures for backend testing."""

import os
import pytest
from starlette.testclient import TestClient

# Set testing environment variables before importing app
os.environ["ENVIRONMENT"] = "testing"
os.environ["DATABASE_URL"] = "sqlite:///./test_sms_shield.db"

from app.main import app
from app.core.database import get_db, SessionLocal, engine
from app.models.base import Base


@pytest.fixture(autouse=True)
def setup_test_database():
    """Create all tables before testing and clean up after."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    if os.path.exists("./test_sms_shield.db"):
        try:
            os.remove("./test_sms_shield.db")
        except PermissionError:
            pass


@pytest.fixture
def client():
    """Yield a TestClient for testing FastAPI endpoints."""
    with TestClient(app) as test_client:
        yield test_client
