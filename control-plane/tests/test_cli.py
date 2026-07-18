"""
Unit tests for the headless CLI — manifest→graph parsing, context loading,
and gating logic. Pure functions plus main() with --manifests, so no cluster,
DB, or network is needed.
"""

import json

import yaml

import pytest

from app import cli
from app.cli import build_graph_from_manifests, load_context, main

RISKY_MANIFESTS = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wide-open
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: wide-open-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: wide-open
subjects:
  - kind: ServiceAccount
    name: default
    namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: team-a
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secret-reader-binding
  namespace: team-a
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: secret-reader
subjects:
  - kind: ServiceAccount
    name: app
    namespace: team-a
"""

CLEAN_MANIFESTS = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: safe-viewer
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: safe-viewer-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: safe-viewer
subjects:
  - kind: User
    name: viewer
    apiGroup: rbac.authorization.k8s.io
"""


@pytest.fixture
def risky_dir(tmp_path):
    (tmp_path / "rbac.yaml").write_text(RISKY_MANIFESTS)
    return tmp_path


@pytest.fixture
def clean_dir(tmp_path):
    (tmp_path / "rbac.yaml").write_text(CLEAN_MANIFESTS)
    return tmp_path


def test_manifest_parsing_builds_graph_shape(risky_dir):
    graph = build_graph_from_manifests(str(risky_dir))

    assert [r["name"] for r in graph["cluster_roles"]] == ["wide-open"]
    assert [r["name"] for r in graph["roles"]] == ["secret-reader"]
    assert graph["roles"][0]["namespace"] == "team-a"
    # camelCase manifest keys must land in the snake_case rule shape
    rule = graph["cluster_roles"][0]["rules"][0]
    assert rule["api_groups"] == ["*"]
    assert rule["resource_names"] == []
    binding = graph["cluster_role_bindings"][0]
    assert binding["roleRef"]["name"] == "wide-open"
    assert binding["subjects"][0]["kind"] == "ServiceAccount"


def test_non_rbac_and_list_documents(tmp_path):
    (tmp_path / "mixed.yaml").write_text("""
apiVersion: v1
kind: List
items:
  - apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata:
      name: from-list
    rules:
      - apiGroups: [""]
        resources: ["pods"]
        verbs: ["get"]
  - apiVersion: v1
    kind: ConfigMap
    metadata:
      name: ignored
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: also-ignored
""")

    graph = build_graph_from_manifests(str(tmp_path))

    assert [r["name"] for r in graph["cluster_roles"]] == ["from-list"]
    assert graph["roles"] == []


def test_context_file_loading_and_validation(tmp_path):
    ctx_file = tmp_path / "kaaval.yaml"
    ctx_file.write_text(
        "environment: dev\ndata_classification: public\n"
        "compliance_scope: []\nexposure: internal\nfail_on_score: 12\n"
    )

    context = load_context(str(ctx_file))

    assert context["environment"] == "dev"
    assert context["_fail_on_score"] == 12


def test_doctor_all_green(monkeypatch, capsys):
    report = {
        "status": "ok",
        "checks": [
            {
                "name": "postgres",
                "ok": True,
                "required": True,
                "detail": "reachable at postgresql://kaaval:***@postgres/kaaval_db",
            },
            {
                "name": "cve-feeds",
                "ok": True,
                "required": False,
                "detail": "2 feed(s) enabled, newest refresh 2026-07-18T12:00:00Z",
            },
            {
                "name": "kubernetes",
                "ok": True,
                "required": False,
                "detail": "local kubeconfig",
            },
        ],
    }
    monkeypatch.setattr(cli, "run_deep_checks", lambda engine, session_factory: report)

    assert main(["doctor"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "✓ postgres: reachable at postgresql://kaaval:***@postgres/kaaval_db",
        "✓ cve-feeds: 2 feed(s) enabled, newest refresh 2026-07-18T12:00:00Z",
        "✓ kubernetes: local kubeconfig",
    ]


def test_doctor_postgres_down_exits_2_with_fix(monkeypatch, capsys):
    fix = "Start the bundled database: `cd deploy && docker compose up -d postgres`."
    report = {
        "status": "error",
        "checks": [
            {
                "name": "postgres",
                "ok": False,
                "required": True,
                "detail": "cannot connect to postgresql://kaaval:***@postgres/kaaval_db (OperationalError)",
                "fix": fix,
            },
            {
                "name": "cve-feeds",
                "ok": False,
                "required": False,
                "detail": "skipped — database unreachable",
                "fix": fix,
            },
            {
                "name": "kubernetes",
                "ok": True,
                "required": False,
                "detail": "in-cluster ServiceAccount credentials",
            },
        ],
    }
    monkeypatch.setattr(cli, "run_deep_checks", lambda engine, session_factory: report)

    assert main(["doctor"]) == 2
    output = capsys.readouterr().out
    assert "✗ postgres:" in output
    assert "docker compose up -d postgres" in output
    assert "✓ kubernetes: in-cluster ServiceAccount credentials" in output


def test_invalid_context_value_is_a_usage_error(tmp_path):
    ctx_file = tmp_path / "kaaval.yaml"
    ctx_file.write_text("environment: prod\n")  # not a valid enum value

    with pytest.raises(SystemExit) as exc:
        load_context(str(ctx_file))
    assert exc.value.code == 2


def test_gate_fails_on_risky_manifests(risky_dir, capsys):
    code = main(["scan", "rbac", "--manifests", str(risky_dir), "--fail-on-score", "10", "--output", "json"])

    assert code == 1
    result = json.loads(capsys.readouterr().out)
    assert result["mode"] == "manifests"
    assert result["affected_count"] >= 2
    rule_types = {f["rule_type"] for f in result["findings"]}
    assert {"wildcard_permissions", "cluster_admin_binding", "broad_secrets_access"} <= rule_types
    # every finding carries remediation for downstream pipeline consumers
    assert all(f["remediation"]["action"] for f in result["findings"])


def test_gate_passes_on_clean_manifests(clean_dir):
    assert main(["scan", "rbac", "--manifests", str(clean_dir), "--fail-on-score", "10"]) == 0


def test_severity_gate(risky_dir):
    assert main(["scan", "rbac", "--manifests", str(risky_dir), "--fail-on-severity", "CRITICAL"]) == 1
    # case-insensitive
    assert main(["scan", "rbac", "--manifests", str(risky_dir), "--fail-on-severity", "critical"]) == 1


def test_no_gate_flags_means_exit_zero_even_with_findings(risky_dir):
    assert main(["scan", "rbac", "--manifests", str(risky_dir)]) == 0


def test_context_file_threshold_applies_without_flag(risky_dir, tmp_path):
    ctx_file = tmp_path / "kaaval.yaml"
    ctx_file.write_text("environment: production\nfail_on_score: 5\n")

    assert main(["scan", "rbac", "--manifests", str(risky_dir), "--context-file", str(ctx_file)]) == 1


def test_sarif_output_is_valid_shape(risky_dir, capsys):
    code = main(["scan", "rbac", "--manifests", str(risky_dir), "--output", "sarif"])

    sarif = json.loads(capsys.readouterr().out)

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Kaaval"
    rules = run["tool"]["driver"]["rules"]
    assert rules, "expected at least one rule"
    assert all("id" in r and "shortDescription" in r for r in rules)

    results = run["results"]
    assert len(results) >= 1
    for r in results:
        assert r["ruleId"] in {rule["id"] for rule in rules}
        assert r["level"] in {"error", "warning", "note", "none"}
        assert r["message"]["text"]
        assert r["locations"][0]["logicalLocations"][0]["name"]

    # sarif output must still not affect the gate's exit code semantics
    assert code == 0  # no --fail-on-score/--fail-on-severity passed here

def test_sarif_output_security_severity_is_valid(risky_dir, capsys):
    code = main(["scan", "rbac", "--manifests", str(risky_dir), "--output", "sarif"])

    sarif = json.loads(capsys.readouterr().out)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]

    for rule in rules:
        assert "security-severity" in rule["properties"]
        sev = float(rule["properties"]["security-severity"])
        assert 0.0 <= sev <= 10.0

def test_policyreport_output_matches_wgpolicy_schema(risky_dir, capsys):
    code = main(["scan", "rbac", "--manifests", str(risky_dir), "--output", "policyreport"])

    docs = list(yaml.safe_load_all(capsys.readouterr().out))
    assert docs, "expected at least one report document"

    kinds = {d["kind"] for d in docs}
    assert "ClusterPolicyReport" in kinds  # wide-open-binding findings are cluster-scoped
    assert "PolicyReport" in kinds  # the team-a secret-reader finding is namespaced

    for d in docs:
        assert d["apiVersion"] == "wgpolicyk8s.io/v1alpha2"
        assert d["summary"]["fail"] == len(d["results"])
        if d["kind"] == "PolicyReport":
            assert d["metadata"]["namespace"]
        for r in d["results"]:
            assert r["result"] == "fail"
            assert r["severity"] in {"critical", "high", "medium", "low", "info"}
            assert r["policy"] and r["message"]
            # the CRD requires string-valued properties
            assert all(isinstance(v, str) for v in r["properties"].values())
            ref = r["resources"][0]
            assert ref["kind"] in {"RoleBinding", "ClusterRoleBinding"}
            if d["kind"] == "PolicyReport":
                assert ref["namespace"] == d["metadata"]["namespace"]

    assert code == 0  # output format must not affect gate semantics


def test_version_flag_prints_single_sourced_version(capsys):
    from app import __version__

    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert capsys.readouterr().out.strip() == f"kaaval {__version__}"


def test_junit_output_is_valid_shape(risky_dir, capsys):
    import xml.etree.ElementTree as ET

    code = main(["scan", "rbac", "--manifests", str(risky_dir), "--output", "junit"])
    assert code == 0  # output format must not affect gate semantics

    suite = ET.fromstring(capsys.readouterr().out)
    assert suite.tag == "testsuite"
    cases = suite.findall("testcase")
    assert cases
    assert suite.get("tests") == str(len(cases))
    assert suite.get("failures") == str(len(cases))
    for case in cases:
        assert case.get("classname", "").startswith("kaaval.rbac.")
        failure = case.find("failure")
        assert failure is not None
        assert failure.get("message")
        assert failure.text  # remediation + binding location body


def test_junit_clean_scan_emits_single_passing_case(tmp_path, capsys):
    import xml.etree.ElementTree as ET

    clean = tmp_path / "clean.yaml"
    clean.write_text("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: clean\n")

    code = main(["scan", "rbac", "--manifests", str(clean), "--output", "junit"])
    assert code == 0

    suite = ET.fromstring(capsys.readouterr().out)
    assert suite.get("tests") == "1"
    assert suite.get("failures") == "0"
    assert suite.find("testcase").find("failure") is None
