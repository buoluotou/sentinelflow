"""Step 11.5: RiskSummary provider/protocol regression (mock only).

Proves the frozen risk_summary contract holds end to end under mock
conditions — the exact JSON a compliant model must emit, and every way a
non-compliant one can fail:

- risk_score injection rejected (EventRisk.score is the only official score)
- unknown risk drivers rejected (no lowercase/trim/guessing coercion)
- confidence bounded to [0, 1]
- key_findings bounded to 1..5
- analyst_priority limited to the frozen enum
- provider failures (Config / Unavailable / Parse) never persist a row

No real model, no network: JsonEchoProvider replays canned model output
through the same parse path the real providers use, and failing providers
run against the service with an isolated in-memory DB.
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import AIRiskSummary, Alert, AlertGroup, EventRisk
from app.services.ai import (
    AIProviderConfigError,
    AIProviderUnavailable,
    AIResponseParseError,
    AIRiskSummaryService,
    RISK_DRIVERS,
    MockProvider,
    RiskSummary,
    parse_risk_summary,
)
from app.services.ai.base import AIProvider
from app.services.ai.models import AIRequest
from app.services.ai.protocol import parse_task_output

#: A compliant model answer, exactly as frozen in Step 11.
VALID_SUMMARY_JSON = json.dumps(
    {
        "summary": (
            "Repeated external authentication failures indicate elevated "
            "compromise risk."
        ),
        "key_findings": [
            "Repeated SSH login failures",
            "Source address is externally reachable",
        ],
        "risk_drivers": ["high_frequency", "public_source"],
        "analyst_priority": "high",
        "confidence": 0.92,
    }
)


def _summary_dict(**overrides) -> dict:
    base = {
        "summary": "Repeated external authentication failures.",
        "key_findings": ["Repeated SSH login failures"],
        "risk_drivers": ["high_frequency"],
        "analyst_priority": "high",
        "confidence": 0.9,
    }
    base.update(overrides)
    return base


class JsonEchoProvider(AIProvider):
    """Replays a canned raw model answer through the real parse path —
    the closest mock stand-in for a live model."""

    name = "json-echo"

    def __init__(self, raw: str):
        super().__init__("json-echo-deterministic")
        self._raw = raw

    def generate(self, request: AIRequest):
        return parse_task_output(request.task, self._raw)


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    from app.core.database import Base

    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _seed(db_session: Session) -> AlertGroup:
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint="a" * 64,
        title="SSH brute force from public source",
        category="authentication",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    db_session.add_all(
        [
            group,
            EventRisk(
                alert_group=group,
                score=80,
                level="high",
                factors=[
                    {"name": "severity", "score": 50, "reason": "Alert severity is high"},
                    {"name": "frequency", "score": 10, "reason": "21-50 alerts observed"},
                    {"name": "public_source", "score": 20, "reason": "public source IP"},
                ],
            ),
            Alert(
                source="scenario-simulator",
                event_type="ssh_failed_login",
                severity="high",
                source_ip="8.8.8.8",
                user_name="root",
                first_seen_at=now,
                last_seen_at=now + timedelta(seconds=5),
                alert_group=group,
            ),
        ]
    )
    db_session.commit()
    return group


def _generate(db_session: Session, provider: AIProvider) -> AIRiskSummary:
    group = _seed(db_session)
    service = AIRiskSummaryService(provider=provider)
    record = service.generate_risk_summary(db_session, group.id)
    db_session.commit()
    return record


# ------------------------------------------------- 11.5.1 valid protocol path


class TestValidRiskSummaryProtocol:
    def test_frozen_example_parses(self):
        summary = parse_risk_summary(VALID_SUMMARY_JSON)
        assert isinstance(summary, RiskSummary)
        assert summary.confidence == 0.92
        assert summary.analyst_priority == "high"
        assert set(summary.risk_drivers) <= RISK_DRIVERS
        assert summary.key_findings == [
            "Repeated SSH login failures",
            "Source address is externally reachable",
        ]

    def test_task_dispatch_parses_risk_summary_only(self):
        summary = parse_task_output("risk_summary", VALID_SUMMARY_JSON)
        assert isinstance(summary, RiskSummary)


def test_valid_json_persists_via_service(db_session):
    record = _generate(db_session, JsonEchoProvider(VALID_SUMMARY_JSON))
    assert record.provider == "json-echo"
    assert record.analyst_priority == "high"
    assert record.risk_drivers == ["high_frequency", "public_source"]
    assert record.confidence == pytest.approx(0.92)
    assert db_session.query(AIRiskSummary).count() == 1


# ----------------------------------- 11.5.2 the AI may never emit risk_score


class TestRiskScoreForbidden:
    def test_parser_rejects_injected_risk_score(self):
        with pytest.raises(AIResponseParseError):
            parse_risk_summary(json.dumps(_summary_dict(risk_score=93)))

    def test_service_persists_nothing_on_risk_score_injection(self, db_session):
        raw = json.dumps(_summary_dict(risk_score=93))
        with pytest.raises(AIResponseParseError):
            _generate(db_session, JsonEchoProvider(raw))
        assert db_session.query(AIRiskSummary).count() == 0


# ------------------------------------------------- 11.5.3 driver vocabulary


class TestRiskDriverVocabulary:
    @pytest.mark.parametrize("driver", ["high_frequency", "public_source", "severity"])
    def test_frozen_drivers_accepted(self, driver):
        summary = parse_risk_summary(json.dumps(_summary_dict(risk_drivers=[driver])))
        assert summary.risk_drivers == [driver]

    @pytest.mark.parametrize("driver", ["credential_attack", "magic_driver", "network_threat"])
    def test_unknown_drivers_rejected(self, driver):
        with pytest.raises(AIResponseParseError, match="unknown risk drivers"):
            parse_risk_summary(json.dumps(_summary_dict(risk_drivers=[driver])))

    @pytest.mark.parametrize("mangled", ["HIGH_FREQUENCY", " high_frequency ", "High_Frequency"])
    def test_no_coercion_of_mangled_drivers(self, mangled):
        """No lowercase / trim / guess-and-map — unknown is unknown."""
        with pytest.raises(AIResponseParseError):
            parse_risk_summary(json.dumps(_summary_dict(risk_drivers=[mangled])))


# ------------------------------------------------------ 11.5.4 confidence


class TestConfidenceBounds:
    @pytest.mark.parametrize("value", [0.0, 0.5, 1.0])
    def test_bounds_inclusive(self, value):
        assert parse_risk_summary(json.dumps(_summary_dict(confidence=value))).confidence == value

    @pytest.mark.parametrize("value", [-0.01, 1.01])
    def test_out_of_bounds_rejected(self, value):
        with pytest.raises(AIResponseParseError):
            parse_risk_summary(json.dumps(_summary_dict(confidence=value)))


# ---------------------------------------------------- 11.5.5 key_findings


class TestKeyFindingsBounds:
    def test_empty_rejected(self):
        with pytest.raises(AIResponseParseError):
            parse_risk_summary(json.dumps(_summary_dict(key_findings=[])))

    @pytest.mark.parametrize("count", [1, 5])
    def test_one_and_five_accepted(self, count):
        findings = [f"finding {i}" for i in range(count)]
        summary = parse_risk_summary(json.dumps(_summary_dict(key_findings=findings)))
        assert len(summary.key_findings) == count

    def test_six_rejected(self):
        findings = [f"finding {i}" for i in range(6)]
        with pytest.raises(AIResponseParseError):
            parse_risk_summary(json.dumps(_summary_dict(key_findings=findings)))


# ------------------------------------------------ 11.5.6 analyst_priority


class TestAnalystPriorityEnum:
    @pytest.mark.parametrize("priority", ["low", "medium", "high", "critical"])
    def test_frozen_values_accepted(self, priority):
        summary = parse_risk_summary(json.dumps(_summary_dict(analyst_priority=priority)))
        assert summary.analyst_priority == priority

    @pytest.mark.parametrize("priority", ["urgent", "severe", "unknown"])
    def test_unknown_values_rejected(self, priority):
        """No fuzzy mapping (urgent -> critical etc.) exists in the code."""
        with pytest.raises(AIResponseParseError):
            parse_risk_summary(json.dumps(_summary_dict(analyst_priority=priority)))


# ------------------------------- 11.5.7 provider failures never persist rows


class TestFailuresNeverPersist:
    @pytest.mark.parametrize(
        "error",
        [
            AIProviderConfigError("missing AI_MODEL"),
            AIProviderUnavailable("connection refused"),
            AIResponseParseError("not the frozen protocol"),
        ],
        ids=["config-503", "unavailable-503", "parse-502"],
    )
    def test_provider_error_before_any_add(self, db_session, error):
        broken = MockProvider(fail_with=error)
        with pytest.raises(type(error)):
            _generate(db_session, broken)
        assert db_session.query(AIRiskSummary).count() == 0

    def test_unknown_event_persists_nothing(self, db_session):
        from app.services.ai.service import AIEventNotFound

        service = AIRiskSummaryService(provider=MockProvider())
        with pytest.raises(AIEventNotFound):
            service.generate_risk_summary(db_session, uuid.uuid4())
        assert db_session.query(AIRiskSummary).count() == 0
