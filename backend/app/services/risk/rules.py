"""Risk scoring rules v1.0 (frozen for Phase 1 Step 5.2).

Everything here is deterministic and offline: no GeoIP, no external threat
intelligence. Changing any constant changes scores — bump RULES_VERSION when
doing so.
"""

RULES_VERSION = "1.0"

# 1. Severity base score
SEVERITY_SCORES: dict[str, int] = {
    "low": 10,
    "medium": 30,
    "high": 50,
    "critical": 70,
}

# 2. Frequency bonus by alert_count: (min_count, bonus), evaluated in order,
#    first band whose min_count is <= alert_count wins.
FREQUENCY_BANDS: tuple[tuple[int, int], ...] = (
    (101, 40),
    (51, 30),
    (21, 20),
    (6, 10),
    (1, 0),
)

# 3. Public attack source bonus — applied at most ONCE per event, no matter
#    how many public source IPs the evidence alerts carry.
PUBLIC_SOURCE_BONUS = 20

# 4. Score is always capped into [0, 100]
MAX_SCORE = 100


def frequency_bonus(alert_count: int) -> int:
    """Bonus for repeated alerts (1-5: +0, 6-20: +10, ..., >100: +40)."""
    for min_count, bonus in FREQUENCY_BANDS:
        if alert_count >= min_count:
            return bonus
    return 0


def level_for_score(score: int) -> str:
    """0-30 low, 31-70 medium, 71-90 high, 91-100 critical."""
    if score <= 30:
        return "low"
    if score <= 70:
        return "medium"
    if score <= 90:
        return "high"
    return "critical"
