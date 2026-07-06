"""
Unit tests for the shared remediation builder — pure-function tests over both
finding shapes (CVE and RBAC), no DB or cluster needed.
"""

from app.remediation import CIS_BENCHMARK, build_remediation


def _rbac_finding(rule_type, subjects=None, compliance_scope=None):
    return {
        "rule_type": rule_type,
        "severity": "HIGH",
        "description": "Test detail.",
        "role": {"kind": "ClusterRole", "name": "test-role"},
        "binding": {"kind": "ClusterRoleBinding", "name": "test-binding", "namespace": None},
        "subjects": subjects or [{"kind": "ServiceAccount", "name": "app", "namespace": "team-a"}],
        "contextual_score": 15.75,
        "score_factors": {
            "environment": {"value": "production", "weight": 1.5},
            "data_classification": {"value": "internal", "weight": 1.0},
            "compliance_scope": {"value": compliance_scope or [], "weight": 1.3 if compliance_scope else 1.0},
            "exposure": {"value": "internal", "weight": 1.0},
        },
    }


def _cve_finding(**overrides):
    finding = {
        "cve_id": "CVE-2026-0001",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "contextual_score": 11.25,
        "score_factors": {
            "environment": {"value": "production", "weight": 1.5},
            "data_classification": {"value": "internal", "weight": 1.0},
            "compliance_scope": {"value": [], "weight": 1.0},
            "exposure": {"value": "internal", "weight": 1.0},
        },
        "affected": [{"component": "kubernetes", "version": "1.29.0", "fixed": "1.29.4"}],
        "fixed_in": ["1.29.4"],
    }
    finding.update(overrides)
    return finding


def test_cve_finding_gets_upgrade_action():
    remediation = build_remediation(_cve_finding())

    assert "Upgrade kubernetes to 1.29.4" in remediation["action"]
    assert remediation["benchmark_refs"] == []
    assert "change log" in remediation["audit_note"]


def test_cve_finding_without_fix_tracks_the_cve():
    remediation = build_remediation(_cve_finding(fixed_in=None))

    assert "No fixed version published yet" in remediation["action"]


def test_rbac_finding_maps_to_verified_cis_control():
    remediation = build_remediation(_rbac_finding("wildcard_permissions"))

    refs = remediation["benchmark_refs"]
    assert any(r["id"] == "5.1.3" and r["benchmark"] == CIS_BENCHMARK for r in refs)


def test_every_rbac_rule_type_has_action_and_refs():
    rule_types = [
        "wildcard_permissions", "broad_secrets_access", "exec_attach_grant",
        "cluster_admin_binding", "privilege_escalation_verbs", "node_proxy_access",
        "token_creation", "csr_approval", "webhook_config_access",
        "workload_creation", "pv_creation",
    ]
    for rule_type in rule_types:
        remediation = build_remediation(_rbac_finding(rule_type))
        assert remediation["action"], rule_type
        assert remediation["benchmark_refs"], rule_type
        assert remediation["why_it_matters"], rule_type


def test_exec_attach_cites_good_practices_not_a_cis_id():
    """There is no CIS 5.1 control for exec/attach — the refs must not
    invent one."""
    remediation = build_remediation(_rbac_finding("exec_attach_grant"))

    refs = remediation["benchmark_refs"]
    assert refs
    assert all(r["benchmark"] != CIS_BENCHMARK for r in refs)
    assert any("OWASP" in r["benchmark"] for r in refs)


def test_system_masters_subject_adds_517_ref():
    finding = _rbac_finding(
        "cluster_admin_binding",
        subjects=[{"kind": "Group", "name": "system:masters", "namespace": None}],
    )

    remediation = build_remediation(finding)

    assert any(r["id"] == "5.1.7" for r in remediation["benchmark_refs"])


def test_compliance_scope_produces_rbac_access_control_note():
    finding = _rbac_finding("broad_secrets_access", compliance_scope=["PCI-DSS"])

    remediation = build_remediation(finding)

    assert remediation["compliance_note"]
    assert "Req 7" in remediation["compliance_note"]
    assert "PCI-DSS" in remediation["audit_note"]


def test_cve_compliance_scope_produces_patch_management_note():
    finding = _cve_finding()
    finding["score_factors"]["compliance_scope"] = {"value": ["PCI-DSS"], "weight": 1.3}

    remediation = build_remediation(finding)

    assert "Req 6.2" in remediation["compliance_note"]


def test_why_it_matters_names_elevated_context_factors():
    remediation = build_remediation(_rbac_finding("broad_secrets_access"))

    assert "production environment" in remediation["why_it_matters"]
