"""Pydantic schemas of the Dashboard API."""
from pydantic import BaseModel


class RiskDistribution(BaseModel):
    """Current EventRisk.level counts over all events."""

    critical: int
    high: int
    medium: int
    low: int


class DashboardSummary(BaseModel):
    """GET /dashboard/summary — the Web Console home page snapshot.

open_incidents counts the active cases (status open or in_progress) and
the severity counters break those active cases down. today_alerts and
today_events cover the current UTC day, from 00:00 onward.
"""

    open_incidents: int
    critical_incidents: int
    high_incidents: int
    medium_incidents: int
    today_alerts: int
    today_events: int
    risk_distribution: RiskDistribution
