"""Phase 1 Step 4.2: FingerprintGenerator tests."""

from app.services.deduplication.fingerprint import FingerprintGenerator
from app.services.normalization.models import (
    ActorInfo,
    AssetInfo,
    Category,
    NormalizedAlert,
)


def _make_alert(
    *,
    source: str = "simulator",
    category: Category = Category.AUTHENTICATION,
    title: str = "SSH failed login",
    asset: AssetInfo | None = None,
    actor: ActorInfo | None = None,
    raw_event: dict | None = None,
) -> NormalizedAlert:
    return NormalizedAlert(
        source=source,
        category=category,
        title=title,
        asset=asset or AssetInfo(hostname="server01", ip="192.168.1.10"),
        actor=actor or ActorInfo(ip="10.10.10.5", user="root"),
        raw_event=raw_event or {},
    )


def test_same_alert_same_fingerprint():
    alert = _make_alert()

    fp1 = FingerprintGenerator.generate(alert)
    fp2 = FingerprintGenerator.generate(alert)

    assert fp1 == fp2


def test_equal_alerts_built_separately_same_fingerprint():
    fp1 = FingerprintGenerator.generate(_make_alert())
    fp2 = FingerprintGenerator.generate(_make_alert())

    assert fp1 == fp2


def test_different_actor_ip_different_fingerprint():
    fp1 = FingerprintGenerator.generate(_make_alert(actor=ActorInfo(ip="10.10.10.5")))
    fp2 = FingerprintGenerator.generate(_make_alert(actor=ActorInfo(ip="10.10.10.6")))

    assert fp1 != fp2


def test_field_order_does_not_matter():
    # sort_keys=True must make the fingerprint independent from key order.
    a = _make_alert(asset=AssetInfo(hostname="server01", ip="1.1.1.1"))
    b = _make_alert(asset=AssetInfo(ip="1.1.1.1", hostname="server01"))

    assert FingerprintGenerator.generate(a) == FingerprintGenerator.generate(b)


def test_volatile_fields_do_not_change_fingerprint():
    """timestamp / raw_event / event_id vary per event and must not
    participate, otherwise every repeat would get a new fingerprint."""
    base = _make_alert()
    fp_base = FingerprintGenerator.generate(base)

    different_raw = _make_alert(
        raw_event={"attempts": 99, "when": "2026-08-24T12:00:00Z"}
    )
    assert FingerprintGenerator.generate(different_raw) == fp_base
    assert different_raw.event_id != base.event_id
    assert different_raw.normalized_at >= base.normalized_at


def test_identity_fields_do_change_fingerprint():
    fp_base = FingerprintGenerator.generate(_make_alert())

    assert FingerprintGenerator.generate(_make_alert(source="wazuh")) != fp_base
    assert (
        FingerprintGenerator.generate(_make_alert(category=Category.WEB)) != fp_base
    )
    assert (
        FingerprintGenerator.generate(_make_alert(title="Web anomaly")) != fp_base
    )
    assert (
        FingerprintGenerator.generate(_make_alert(asset=AssetInfo(hostname="server02")))
        != fp_base
    )


def test_fingerprint_is_sha256_hex():
    fp = FingerprintGenerator.generate(_make_alert())

    assert len(fp) == 64
    int(fp, 16)  # raises ValueError if not valid hex
