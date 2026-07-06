"""
Unit tests for the Contextual Risk Score formula — the core claim of the
scoring engine (same CVE, different business context, different rank).

Pure-function tests against cve_service directly: no DB, no live cluster,
no CVE feed network access needed, unlike the HTTP-level smoke test.
"""

from app.cve_service import _contextual_score, _match_cves
from app.models import CVEEntry


def test_environment_changes_score():
    prod_score, prod_factors = _contextual_score(7.5, "HIGH", {"environment": "production"})
    dev_score, dev_factors = _contextual_score(7.5, "HIGH", {"environment": "dev"})

    assert prod_score > dev_score
    assert prod_factors["environment"]["weight"] > dev_factors["environment"]["weight"]


def test_data_classification_and_exposure_stack():
    baseline, _ = _contextual_score(7.5, "HIGH", {})
    elevated, factors = _contextual_score(
        7.5, "HIGH",
        {
            "environment": "production",
            "data_classification": "pii",
            "compliance_scope": ["PCI-DSS"],
            "exposure": "internet-facing",
        },
    )

    assert elevated > baseline
    assert factors["data_classification"]["weight"] > 1.0
    assert factors["compliance_scope"]["weight"] > 1.0
    assert factors["exposure"]["weight"] > 1.0


def test_missing_cvss_falls_back_to_severity_band():
    score, factors = _contextual_score(None, "CRITICAL", {})
    assert score > 0
    assert factors["base_severity"]["cvss_score"] is None


def test_match_cves_ranks_by_contextual_score_not_just_severity():
    """
    Two entries with the same HIGH severity/CVSS but different components —
    findings must sort by contextual_score, and each must carry score_factors.
    """
    entries = [
        CVEEntry(cve_id="CVE-1", title="t1", severity="HIGH", cvss_score=7.5,
                 affected_components=[{"component": "kubernetes", "ranges": [{"introduced": "0", "fixed": "9.9.9"}]}],
                 fixed_in=["9.9.9"], description="d", references=[]),
        CVEEntry(cve_id="CVE-2", title="t2", severity="HIGH", cvss_score=7.5,
                 affected_components=[{"component": "kubernetes", "ranges": [{"introduced": "0", "fixed": "9.9.9"}]}],
                 fixed_in=["9.9.9"], description="d", references=[]),
    ]

    findings = _match_cves(
        entries, server_version="1.30.0", node_versions=[], addons=[],
        context={"environment": "production", "exposure": "internet-facing"},
    )

    assert len(findings) == 2
    for f in findings:
        assert "contextual_score" in f
        assert "score_factors" in f
        assert f["score_factors"]["environment"]["value"] == "production"
