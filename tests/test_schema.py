"""Unit tests for schema models."""

from paradox_recon.schema import Category, Finding, PluginResult, Severity, Target


def test_finding_to_dict():
    f = Finding(
        title="Test",
        category=Category.WEB,
        severity=Severity.HIGH,
        score=5.0,
        plugin="web",
    )
    d = f.to_dict()
    assert d["title"] == "Test"
    assert d["category"] == "web"
    assert d["severity"] == "high"
    assert d["score"] == 5.0
    assert "id" in d
    assert "timestamp" in d


def test_target():
    t = Target(raw="https://example.com", hostname="example.com", kind="url", scheme="https")
    d = t.to_dict()
    assert d["hostname"] == "example.com"
    assert d["kind"] == "url"


def test_plugin_result():
    r = PluginResult(plugin="dns", target="example.com", findings=[])
    assert r.success is True
    assert r.to_dict()["plugin"] == "dns"
