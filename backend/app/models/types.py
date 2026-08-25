"""Shared column types for SentinelFlow ORM models.

JSONVariant lives in its own module (importable by every model) so child
models like AIAnalysis never trigger the alert -> alert_group circular
import chain.
"""
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB

# JSONB on PostgreSQL, plain JSON on other dialects (e.g. SQLite in tests).
JSONVariant = JSON().with_variant(JSONB(), "postgresql")
