"""Stable fingerprint generation for normalized alerts.

Phase 1 Step 4.2: a fingerprint identifies *a kind of event* (same source,
category, title, asset, actor) and is stable over time. It is NOT a group
identifier: the same fingerprint can belong to multiple AlertGroups — the
time-window based grouping is the deduplication engine's job (Step 4.3).
"""

import hashlib
import json

from app.services.normalization.models import NormalizedAlert


class FingerprintGenerator:
    """Generate a stable SHA256 fingerprint for a normalized alert."""

    @staticmethod
    def generate(alert: NormalizedAlert) -> str:
        """Return the 64-char hex SHA256 fingerprint of the alert identity.

        Only identity fields participate:
        - source:   which system reported it (simulator, wazuh, ...)
        - category: what kind of attack (authentication, malware, ...)
        - title:    which rule fired ("SSH failed login")
        - asset:    where it happened (hostname/ip)
        - actor:    who did it (ip/user)

        Volatile fields (timestamp, raw_event, event_id, observables) are
        excluded on purpose — they change per event and would defeat dedup.
        """
        payload = {
            "source": alert.source,
            "category": alert.category.value,
            "title": alert.title,
            "asset": alert.asset.model_dump() if alert.asset else None,
            "actor": alert.actor.model_dump() if alert.actor else None,
        }

        # sort_keys makes the fingerprint independent from field order.
        normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
