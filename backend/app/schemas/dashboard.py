"""Pydantic schemas of the Dashboard API (Phase 1 Step 7.5)."""
from pydantic import BaseModel


class RiskDistribution(BaseModel):
    """Current EventRisk.level counts over all events."""

    critical: int
    high: int
    medium: int
    low: int


class DashboardSummary(BaseModel):
    """GET /dashboard/summary — the Web Console home page snapshot.

    open_incidents counts ACTIVE cases (status open + in_progress); the
    severity counters break those active cases down. today_* metrics are
    since today 00:00 UTC.
    """

    open_incidents: int
    critical_incidents: int
    high_incidents: int
    medium_incidents: int
    today_alerts: int
    today_events: int
    risk_distribution: RiskDistribution
