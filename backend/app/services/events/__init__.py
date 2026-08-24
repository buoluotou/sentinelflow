"""Security events query layer (Phase 1 Step 4.4)."""

from app.services.events.service import get_event, list_events

__all__ = ["get_event", "list_events"]
