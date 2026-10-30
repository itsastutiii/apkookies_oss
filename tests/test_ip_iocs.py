"""Bare dotted numbers are not hardcoded C2 IPs (version strings like 1.10.12.0 matched)."""
from backend.static_analysis import ioc_extraction


def _by_type(strings):
    rep = ioc_extraction.extract(strings)
    return {t: sorted(i.value for i in rep.iocs if i.type == t) for t in ("ip", "ip_like")}


def test_only_network_context_makes_an_ip():
    got = _by_type([
        "1.10.12.0",                       # version string
        "build 2.4.11.3 release",          # version in text
        "http://45.9.148.12/gate.php",     # URL host
        "45.9.148.13:8080",                # socket / connection string
        "tcp://45.9.148.14:443",           # URL with scheme and port
    ])
    assert got["ip"] == ["45.9.148.12", "45.9.148.13", "45.9.148.14"]
    assert got["ip_like"] == ["1.10.12.0", "2.4.11.3"]


def test_ip_like_never_feeds_rules_or_model():
    from backend.scoring import rules_engine
    from backend.scoring.features import build_features
    from tests.test_scoring import _a11y_bundle
    b = _a11y_bundle(iocs=ioc_extraction.extract(["1.10.12.0"]).iocs)
    assert set(h.rule_id for h in rules_engine.evaluate(b) if h.rule_id.startswith("R002")) == {
        "R002B_A11Y_OVERLAY_ALONE"}                                # no "hardcoded IP" second signal
    assert build_features(b).ioc_counts.get("ip", 0) == 0


def test_ip_like_is_reported_as_unconfirmed_and_not_exported():
    from backend.threat_intel.stix_export import _pattern_for
    assert _pattern_for("ip_like", "1.10.12.0") is None
    assert ioc_extraction.extract(["1.10.12.0"]).stats.ip_like_unconfirmed == 1
