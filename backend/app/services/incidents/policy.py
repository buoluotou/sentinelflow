"""Incident creation policy v1.0 (Phase 1 Step 7.4).

The policy decides, from the freshly recalculated risk snapshot, whether
the pipeline opens a SOC case automatically:

    EventRisk.score >= AUTO_CREATE_THRESHOLD  ->  create Incident
    otherwise                                 ->  event only

Frozen on SCORE, not severity: the Risk Engine is the single place that
weighs severity + frequency + source, so the policy consumes its output
directly and never re-derives importance on its own.

The policy is evaluated on the write path only (deduplication pipeline,
after every recalculation) — it never backfills legacy events.
"""

#: Score at (and above) which an event automatically becomes a case.
AUTO_CREATE_THRESHOLD = 70


def should_create_incident(score: int) -> bool:
    """True when the event's current risk score warrants a SOC case."""
    return score >= AUTO_CREATE_THRESHOLD
