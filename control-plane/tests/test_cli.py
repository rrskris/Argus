"""
Unit tests for the headless CLI — manifest→graph parsing, context loading,
and gating logic. Pure functions plus main() with --manifests, so no cluster,
DB, or network is needed.
"""

import json

import pytest

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
  - kind: ServiceAccount
    name: viewer
    namespace: default
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
    ctx_file = tmp_path / "argus.yaml"
    ctx_file.write_text(
        "environment: dev\ndata_classification: public\n"
        "compliance_scope: []\nexposure: internal\nfail_on_score: 12\n"
    )

    context = load_context(str(ctx_file))

    assert context["environment"] == "dev"
    assert context["_fail_on_score"] == 12


def test_invalid_context_value_is_a_usage_error(tmp_path):
    ctx_file = tmp_path / "argus.yaml"
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
    ctx_file = tmp_path / "argus.yaml"
    ctx_file.write_text("environment: production\nfail_on_score: 5\n")

    assert main(["scan", "rbac", "--manifests", str(risky_dir), "--context-file", str(ctx_file)]) == 1
def test_sarif_output_is_valid_shape(risky_dir, capsys):
    code = main(["scan", "rbac", "--manifests", str(risky_dir), "--output", "sarif"])

    sarif = json.loads(capsys.readouterr().out)

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Argus"
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