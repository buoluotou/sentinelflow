from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings

# pysqlite defaults to check_same_thread=True, which forbids using a connection
# from any thread other than the one that opened it. Uvicorn runs our sync (def)
# route handlers in an AnyIO worker threadpool, so a pooled SQLite connection is
# routinely reused from a different thread than it was created on. The pool still
# checks a connection out to only ONE thread at a time, so disabling the check is
# the standard, safe FastAPI+SQLite recipe; it makes file-based SQLite viable for
# native dev / demo mode (no PostgreSQL required). The PostgreSQL path is left
# completely untouched — connect_args/pool_kwargs stay empty for non-sqlite URLs.
connect_args = {}
pool_kwargs = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    # An in-memory SQLite database lives inside a single connection. StaticPool
    # keeps exactly one connection shared by every thread so the DB survives
    # across requests; the default SingletonThreadPool would instead hand each
    # thread its own empty database.
    if ":memory:" in settings.DATABASE_URL or settings.DATABASE_URL == "sqlite://":
        pool_kwargs["poolclass"] = StaticPool

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    connect_args=connect_args,
    **pool_kwargs,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    """Declarative base for all SentinelFlow ORM models."""


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
