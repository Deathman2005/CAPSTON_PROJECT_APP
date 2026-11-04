"""Database connection and session management with SQLAlchemy 2.0."""

import time
import logging
from typing import Generator, Dict, Any
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session

from app.core.config import settings

logger = logging.getLogger("smsshield.database")

database_url = settings.DATABASE_URL
# Strip any legacy async driver prefixes if present for sync engine
if "+aiosqlite" in database_url:
    database_url = database_url.replace("+aiosqlite", "")
if "+asyncpg" in database_url:
    database_url = database_url.replace("+asyncpg", "+psycopg")

engine_kwargs: Dict[str, Any] = {
    "echo": settings.DEBUG and settings.ENVIRONMENT == "development",
    "future": True,
}

if "sqlite" in database_url:
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs["pool_pre_ping"] = True
    engine_kwargs["pool_size"] = 10
    engine_kwargs["max_overflow"] = 20

engine = create_engine(database_url, **engine_kwargs)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """Dependency for yielding a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_database_health() -> Dict[str, Any]:
    """
    Check live connectivity to the database by executing SELECT 1.
    Returns status, dialect, and query latency in milliseconds.
    """
    start_time = time.perf_counter()
    try:
        with engine.connect() as conn:
            scalar = conn.execute(text("SELECT 1")).scalar()
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            if scalar == 1:
                return {
                    "status": "connected",
                    "dialect": engine.dialect.name,
                    "latency_ms": latency_ms,
                    "error": None,
                }
            return {
                "status": "unhealthy",
                "dialect": engine.dialect.name,
                "latency_ms": latency_ms,
                "error": "Unexpected query result",
            }
    except Exception as exc:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.error(f"Database health check failed: {exc}")
        return {
            "status": "disconnected",
            "dialect": engine.dialect.name,
            "latency_ms": latency_ms,
            "error": str(exc),
        }
