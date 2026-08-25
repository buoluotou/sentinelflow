"""Phase 1 Step 5.2: RiskEngine rule-based scoring tests."""

from datetime import datetime, timezone

import pytest

from app.models import Alert, AlertGroup
from app.services.risk import engine
from app.services.risk.factors import is_public_ip
from app.services.risk.rules import frequency_bonus, level_for_score

FINGERPRINT = "c" * 64


def _make_group(severity: str = "medium", alert_count: int = 1) -> AlertGroup:
    now = datetime.now(timezone.utc)
    return AlertGroup(
        fingerprint=FINGERPRINT,
        title="SSH failed login",
        category="authentication",
        severity=severity,
        alert_count=alert_count,
        first_seen=now,
        last_seen=now,
    )


def _make_alert(group: AlertGroup, source_ip: str | None = None) -> Alert:
    return Alert(
        source="simulator",
        event_type="ssh_failed_login",
        source_ip=source_ip,
        alert_group=group,
    )


def _factor_scores(result) -> dict[str, int]:
    return {f.name: f.score for f in result.factors}


def test_case1_severity_base(db_session):
    """medium + 1 alert -> base 30 -> level 'low' (0-30 band)."""
    group = _make_group(severity="medium", alert_count=1)
    db_session.add_all([group, _make_alert(group, "10.10.10.5")])
    db_session.commit()

    result = engine.calculate(group, [a for a in group.alerts])
    assert result.score == 30
    assert result.level == "low"
    assert _factor_scores(result) == {
        "severity": 30,
        "frequency": 0,
        "public_source": 0,
    }


def test_case2_high_frequency(db_session):
    """medium + 100 alerts -> 30 + 30 = 60."""
    group = _make_group(severity="medium", alert_count=100)
    db_session.add(group)
    db_session.commit()

    result = engine.calculate(group, group.alerts)
    assert result.score == 60
    assert result.level == "medium"
    assert _factor_scores(result)["frequency"] == 30


def test_case3_public_source(db_session):
    """medium + 100 alerts + public IP -> 30 + 30 + 20 = 80, HIGH."""
    group = _make_group(severity="medium", alert_count=100)
    db_session.add_all([group, _make_alert(group, "8.8.8.8")])
    db_session.commit()

    result = engine.calculate(group, [a for a in group.alerts])
    assert result.score == 80
    assert result.level == "high"
    assert _factor_scores(result)["public_source"] == 20


def test_case3b_public_bonus_applied_once(db_session):
    """Many public source IPs still count as a single +20."""
    group = _make_group(severity="medium", alert_count=100)
    db_session.add_all(
        [group] + [_make_alert(group, f"9.9.9.{i}") for i in range(1, 6)]
    )
    db_session.commit()

    result = engine.calculate(group, [a for a in group.alerts])
    assert _factor_scores(result)["public_source"] == 20
    assert result.score == 80


def test_case4_private_ips_no_bonus(db_session):
    group = _make_group(severity="medium", alert_count=100)
    db_session.add_all(
        [
            group,
            _make_alert(group, "192.168.1.100"),
            _make_alert(group, "10.0.0.9"),
            _make_alert(group, "172.16.0.1"),
            _make_alert(group, "172.31.255.254"),
        ]
    )
    db_session.commit()

    result = engine.calculate(group, [a for a in group.alerts])
    assert _factor_scores(result)["public_source"] == 0
    assert result.score == 60


def test_case5_score_capped_at_100(db_session):
    """critical + >100 alerts + public IP: 70 + 40 + 20 = 130 -> capped."""
    group = _make_group(severity="critical", alert_count=150)
    db_session.add_all([group, _make_alert(group, "104.16.0.1")])
    db_session.commit()

    result = engine.calculate(group, [a for a in group.alerts])
    assert result.score == 100
    assert result.level == "critical"
    # the uncapped factor trail stays fully explainable
    assert sum(f.score for f in result.factors) == 130


def test_case6_invalid_ip_safely_ignored(db_session):
    group = _make_group(severity="medium", alert_count=1)
    db_session.add_all(
        [
            group,
            _make_alert(group, "unknown"),
            _make_alert(group, None),
            _make_alert(group, ""),
        ]
    )
    db_session.commit()

    result = engine.calculate(group, [a for a in group.alerts])
    assert _factor_scores(result)["public_source"] == 0
    assert result.score == 30


def test_factors_structure_is_ai_and_api_ready(db_session):
    group = _make_group(severity="medium", alert_count=100)
    db_session.add_all([group, _make_alert(group, "8.8.8.8")])
    db_session.commit()

    result = engine.calculate(group, [a for a in group.alerts])
    serialized = result.factors_as_dicts()
    assert [f["name"] for f in serialized] == [
        "severity",
        "frequency",
        "public_source",
    ]
    for item in serialized:
        assert set(item) == {"name", "score", "reason"}
        assert isinstance(item["reason"], str) and item["reason"]
    assert sum(f["score"] for f in serialized) == result.score


@pytest.mark.parametrize(
    "value,expected",
    [
        ("8.8.8.8", True),
        ("1.1.1.1", True),
        ("9.9.9.9", True),
        ("192.168.1.1", False),
        ("10.255.0.1", False),
        ("172.16.0.1", False),
        ("172.31.255.254", False),
        ("127.0.0.1", False),          # loopback
        ("169.254.10.10", False),      # link-local
        ("224.0.0.1", False),          # multicast
        ("0.0.0.0", False),            # unspecified
        ("240.0.0.1", False),          # reserved
        ("100.64.0.1", False),         # CGNAT, not publicly routable
        ("203.0.113.7", False),        # TEST-NET documentation range
        ("198.51.100.23", False),      # TEST-NET documentation range
        ("unknown", False),
        ("", False),
        (None, False),
    ],
)
def test_is_public_ip_classification(value, expected):
    assert is_public_ip(value) is expected


@pytest.mark.parametrize(
    "count,bonus",
    [(1, 0), (5, 0), (6, 10), (20, 10), (21, 20), (50, 20), (51, 30),
     (100, 30), (101, 40), (10_000, 40)],
)
def test_frequency_band_boundaries(count, bonus):
    assert frequency_bonus(count) == bonus


@pytest.mark.parametrize(
    "score,level",
    [(0, "low"), (30, "low"), (31, "medium"), (70, "medium"),
     (71, "high"), (90, "high"), (91, "critical"), (100, "critical")],
)
def test_level_threshold_boundaries(score, level):
    assert level_for_score(score) == level
