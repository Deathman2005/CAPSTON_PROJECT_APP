"""Direct tests for database connectivity and health pinging."""

from sqlalchemy import text
from app.core.database import check_database_health, get_db


def test_database_health_check_function():
    """Verify check_database_health executes SELECT 1 and returns structured health dictionary."""
    result = check_database_health()
    assert result["status"] == "connected"
    assert result["dialect"] in ("sqlite", "postgresql")
    assert isinstance(result["latency_ms"], float)
    assert result["error"] is None


def test_database_session_dependency():
    """Verify get_db dependency yields a functional session."""
    generator = get_db()
    session = next(generator)
    try:
        query_result = session.execute(text("SELECT 42 AS answer"))
        row = query_result.mappings().first()
        assert row["answer"] == 42
    finally:
        try:
            next(generator)
        except StopIteration:
            pass
