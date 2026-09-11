"""Dashboard aggregation services.

One aggregated snapshot for the Web Console home page, computed in the
backend so the frontend never assembles metrics from multiple endpoints.
"""

from app.services.dashboard.service import get_summary

__all__ = ["get_summary"]
