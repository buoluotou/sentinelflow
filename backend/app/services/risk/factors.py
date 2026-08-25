"""Individual risk factors — one function per factor.

Each function returns a RiskFactor with score 0 when it does not apply, so
the engine can always render the complete, explainable factor trail.
Future factors (asset criticality, multiple accounts, MITRE technique, ...)
are added here as new functions without touching the existing ones.
"""
from ipaddress import ip_address, ip_network

from app.models import Alert, AlertGroup
from app.services.risk.models import RiskFactor
from app.services.risk.rules import (
    PUBLIC_SOURCE_BONUS,
    SEVERITY_SCORES,
    frequency_bonus,
)


def parse_ip(value: str | None):
    """Best-effort IP parse: invalid/empty input returns None, never raises."""
    if not value or not isinstance(value, str):
        return None
    try:
        return ip_address(value.strip())
    except ValueError:
        return None


# Ranges that are NOT public attack sources but which stdlib flags do not
# reliably cover across Python versions (e.g. on 3.12.x 100.64/10 is neither
# private nor reserved). Listed explicitly for deterministic behaviour.
_NON_PUBLIC_NETWORKS = (
    ip_network("100.64.0.0/10"),    # CGNAT / shared address space (RFC 6598)
    ip_network("192.0.2.0/24"),     # TEST-NET-1 documentation
    ip_network("198.51.100.0/24"),  # TEST-NET-2 documentation
    ip_network("203.0.113.0/24"),   # TEST-NET-3 documentation
)


def is_public_ip(value: str | None) -> bool:
    """True only for addresses treated as public attack sources.

    Explicit exclusion list per the Step 5.2 spec: private ranges, loopback,
    link-local, multicast, reserved, unspecified — plus CGNAT and TEST-NET
    documentation ranges which are not routable either. We deliberately do
    NOT rely on ``is_global`` alone: some Python versions (e.g. 3.12.x)
    classify multicast addresses as global and CGNAT as non-private.
    """
    ip = parse_ip(value)
    if ip is None:
        return False
    excluded = (
        ip.is_private,
        ip.is_loopback,
        ip.is_link_local,
        ip.is_multicast,
        ip.is_reserved,
        ip.is_unspecified,
        any(ip in net for net in _NON_PUBLIC_NETWORKS),
    )
    return not any(excluded)


def severity_factor(group: AlertGroup) -> RiskFactor:
    """Base score derived from the event severity."""
    score = SEVERITY_SCORES.get(group.severity, SEVERITY_SCORES["medium"])
    return RiskFactor(
        name="severity",
        score=score,
        reason=f"Alert severity is {group.severity}",
    )


def frequency_factor(group: AlertGroup) -> RiskFactor:
    """Bonus for a high number of aggregated alerts."""
    bonus = frequency_bonus(group.alert_count)
    return RiskFactor(
        name="frequency",
        score=bonus,
        reason=f"{group.alert_count} alerts observed in this event",
    )


def public_source_factor(alerts: list[Alert]) -> RiskFactor:
    """Bonus when at least one evidence alert originates from a public IP.

    Applied at most once per event, regardless of how many public sources.
    """
    public_ips = sorted(
        {a.source_ip for a in alerts if is_public_ip(a.source_ip)}
    )
    if not public_ips:
        return RiskFactor(
            name="public_source", score=0, reason="No public source IP detected"
        )
    return RiskFactor(
        name="public_source",
        score=PUBLIC_SOURCE_BONUS,
        reason=f"Public source IP detected: {public_ips[0]}",
    )
