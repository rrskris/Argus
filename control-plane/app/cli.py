"""
Kaaval CLI — headless scanning for CI/CD pipelines.

Runs the same pure rule engine and Contextual Risk Score the server uses,
with no database, auth, or running control plane:

    # live cluster (CI service-account kubeconfig)
    python -m app.cli scan rbac --kubeconfig ./ci-kubeconfig

    # static manifests, before they ever reach a cluster (shift-left)
    python -m app.cli scan rbac --manifests ./k8s/

    # gate the pipeline on contextually scored risk
    python -m app.cli scan rbac --manifests ./k8s/ \
        --context-file kaaval.yaml --fail-on-score 20 --output json

The risk context lives in a versioned file in the app repo (kaaval.yaml):

    environment: production          # production | staging | dev
    data_classification: pii         # public | internal | pii | financial | phi
    compliance_scope: [PCI-DSS]
    exposure: internet-facing        # internet-facing | internal
    fail_on_score: 20                # optional; CLI flags override
    fail_on_severity: HIGH           # optional

That is the point of gating on Kaaval instead of a flat severity threshold:
the same wildcard ClusterRole that hard-fails a production/PCI pipeline can
pass with a warning in dev, because the context says so.

Exit codes: 0 clean/below threshold, 1 threshold breached, 2 usage error.
"""

import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

from . import __version__
from .rbac_service import evaluate_rbac_findings
from .scoring import (
    MAX_CONTEXTUAL_SCORE,
    SEVERITY_ORDER,
    VALID_DATA_CLASSIFICATIONS,
    VALID_ENVIRONMENTS,
    VALID_EXPOSURES,
)

_DEFAULT_CONTEXT = {
    "environment": "production",
    "data_classification": "internal",
    "compliance_scope": [],
    "exposure": "internal",
}

_RBAC_KINDS = {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}


def _fail_usage(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    sys.exit(2)


def _fail_unreadable_manifests(path_str: str) -> None:
    print(f"error: cannot read manifests path '{path_str}': permission denied", file=sys.stderr)
    print("hint: on SELinux hosts, mount volumes with ':z' — e.g. -v \"$PWD/k8s:/scan:z\"", file=sys.stderr)
    sys.exit(2)


# ── Risk context ───────────────────────────────────────────────────────────────

def load_context(path: str | None) -> dict:
    """Load and validate the risk-context file; defaults + warning if absent."""
    if not path:
        print(
            "warning: no --context-file given — scoring with defaults "
            f"({_DEFAULT_CONTEXT['environment']}/{_DEFAULT_CONTEXT['data_classification']}/"
            f"{_DEFAULT_CONTEXT['exposure']}, no compliance scope). "
            "Commit a kaaval.yaml for context-aware gating.",
            file=sys.stderr,
        )
        return dict(_DEFAULT_CONTEXT)

    try:
        data = yaml.safe_load(Path(path).read_text()) or {}
    except FileNotFoundError:
        _fail_usage(f"context file not found: {path}")
    except yaml.YAMLError as exc:
        _fail_usage(f"context file is not valid YAML: {exc}")

    context = {**_DEFAULT_CONTEXT, **{k: v for k, v in data.items() if k in _DEFAULT_CONTEXT}}
    if context["environment"] not in VALID_ENVIRONMENTS:
        _fail_usage(f"environment must be one of {sorted(VALID_ENVIRONMENTS)}")
    if context["data_classification"] not in VALID_DATA_CLASSIFICATIONS:
        _fail_usage(f"data_classification must be one of {sorted(VALID_DATA_CLASSIFICATIONS)}")
    if context["exposure"] not in VALID_EXPOSURES:
        _fail_usage(f"exposure must be one of {sorted(VALID_EXPOSURES)}")
    if not isinstance(context["compliance_scope"], list):
        _fail_usage("compliance_scope must be a list")

    # Gating thresholds may live in the context file too; flags override.
    context["_fail_on_score"] = data.get("fail_on_score")
    context["_fail_on_severity"] = data.get("fail_on_severity")
    return context


# ── Manifest (shift-left) mode ────────────────────────────────────────────────

def _rule_dict(rule: dict) -> dict:
    """Raw manifest rule (camelCase) → the shape K8sClient emits (snake_case)."""
    return {
        "verbs": rule.get("verbs") or [],
        "resources": rule.get("resources") or [],
        "api_groups": rule.get("apiGroups") or [],
        "resource_names": rule.get("resourceNames") or [],
    }


def _iter_manifest_docs(root: Path):
    files = (
        [root] if root.is_file()
        else sorted(p for ext in ("*.yaml", "*.yml") for p in root.rglob(ext))
    )
    for path in files:
        try:
            docs = yaml.safe_load_all(path.read_text())
            for doc in docs:
                if not isinstance(doc, dict):
                    continue
                # Unwrap v1 List objects (kubectl get -o yaml output)
                if doc.get("kind") == "List":
                    yield from (i for i in doc.get("items") or [] if isinstance(i, dict))
                else:
                    yield doc
        except yaml.YAMLError as exc:
            print(f"warning: skipping {path}: invalid YAML ({exc})", file=sys.stderr)


def build_graph_from_manifests(path_str: str) -> dict:
    """Parse RBAC objects from YAML into K8sClient.get_rbac_graph_data()'s shape."""
    root = Path(path_str)
    try:
        root_exists = root.exists()
    except PermissionError:
        _fail_unreadable_manifests(path_str)
    if not root_exists:
        _fail_usage(f"manifests path not found: {path_str}")

    # Path.rglob() silently swallows EACCES during traversal, which would let an
    # unreadable path masquerade as an empty (clean) scan with exit 0. Probe
    # readability explicitly so the user gets a real, actionable error instead.
    try:
        if root.is_dir():
            os.listdir(root)
        else:
            with open(root, "rb"):
                pass
    except PermissionError:
        _fail_unreadable_manifests(path_str)

    graph = {"roles": [], "cluster_roles": [], "role_bindings": [], "cluster_role_bindings": []}
    for doc in _iter_manifest_docs(root):
        kind = doc.get("kind")
        if kind not in _RBAC_KINDS:
            continue
        meta = doc.get("metadata") or {}
        if kind == "Role":
            graph["roles"].append({
                "name": meta.get("name"), "namespace": meta.get("namespace"), "kind": "Role",
                "rules": [_rule_dict(r) for r in doc.get("rules") or []],
            })
        elif kind == "ClusterRole":
            graph["cluster_roles"].append({
                "name": meta.get("name"), "kind": "ClusterRole",
                "rules": [_rule_dict(r) for r in doc.get("rules") or []],
            })
        elif kind == "RoleBinding":
            graph["role_bindings"].append({
                "name": meta.get("name"), "namespace": meta.get("namespace"), "kind": "RoleBinding",
                "roleRef": doc.get("roleRef") or {},
                "subjects": doc.get("subjects") or [],
            })
        elif kind == "ClusterRoleBinding":
            graph["cluster_role_bindings"].append({
                "name": meta.get("name"), "kind": "ClusterRoleBinding",
                "roleRef": doc.get("roleRef") or {},
                "subjects": doc.get("subjects") or [],
            })
    return graph


# ── Live mode ─────────────────────────────────────────────────────────────────

def build_graph_from_cluster(kubeconfig: str | None) -> dict:
    if kubeconfig:
        os.environ["KUBECONFIG"] = kubeconfig
    from .k8s_client import K8sClient  # deferred: needs kube credentials, not needed for --manifests

    k8s = K8sClient()
    if not k8s.authorized:
        _fail_usage("could not load Kubernetes credentials (kubeconfig/in-cluster)")
    graph = k8s.get_rbac_graph_data()
    if "error" in graph:
        _fail_usage(f"could not fetch RBAC data: {graph['error']}")
    return graph


# ── Output + gating ───────────────────────────────────────────────────────────

def _severity_breakdown(findings: list) -> dict:
    breakdown = {s: 0 for s in reversed(SEVERITY_ORDER)}
    for f in findings:
        breakdown[f.get("severity", "UNKNOWN")] = breakdown.get(f.get("severity", "UNKNOWN"), 0) + 1
    return breakdown


def _print_table(result: dict) -> None:
    findings = result["findings"]
    print(f"Kaaval RBAC scan — {result['total_bindings_checked']} bindings checked, "
          f"{len(findings)} findings")
    counts = ", ".join(f"{k}={v}" for k, v in result["severity_breakdown"].items() if v)
    print(f"Severity: {counts or 'none'}\n")
    if not findings:
        print("No RBAC misconfigurations found.")
        return
    for f in findings:
        binding = f["binding"]
        location = f" -n {binding['namespace']}" if binding.get("namespace") else ""
        print(f"[{f['severity']:>8}] risk={f['contextual_score']:<7} {f['title']}")
        print(f"           via {binding['kind']} {binding['name']}{location}")
        print(f"           fix: {f['remediation']['action']}")
        refs = "; ".join(
            f"{r['benchmark']}{' ' + r['id'] if r.get('id') else ''}"
            for r in f["remediation"]["benchmark_refs"]
        )
        if refs:
            print(f"           refs: {refs}")
        print()


_SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "UNKNOWN": "note",
}


def _humanize_rule_type(rule_type: str) -> str:
    """Generic rule-level description from rule_type,
    e.g. 'cluster_admin_binding' -> 'Cluster Admin Binding'."""
    return rule_type.replace("_", " ").title()


def _finding_rows(result: dict) -> list:
    """Normalize findings into a generic row shape shared by SARIF/JUnit formatters."""
    rows = []
    for f in result["findings"]:
        rows.append({
            "rule_id": f["rule_type"],
            "level": _SEVERITY_TO_SARIF_LEVEL.get(f.get("severity", "UNKNOWN"), "note"),
            "title": f["title"],
            "message": f["remediation"]["action"],
            "refs": f["remediation"].get("benchmark_refs") or [],
            "raw": f,
        })
    return rows

def _contextual_score_to_security_severity(score: float, score_cap: float = MAX_CONTEXTUAL_SCORE) -> str:
    """
    Scale Kaaval's Contextual Risk Score (0..score_cap) to GitHub's
    security-severity range (0.0-10.0, CVSS-style string).

    GitHub buckets: >9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, <=3.9 low.
    """
    scaled = min(10.0, max(0.0, (score * 10.0) / score_cap))
    return f"{scaled:.1f}"

def _print_sarif(result: dict) -> None:
    rows = _finding_rows(result)

    rules_by_id = {}
    max_score_by_rule = {}
    for row in rows:
        score = row["raw"].get("contextual_score") or 0.0
        rule_id = row["rule_id"]
        max_score_by_rule[rule_id] = max(max_score_by_rule.get(rule_id, 0.0), score)

        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": _humanize_rule_type(rule_id)},
                "helpUri": "https://github.com/kaaval/kaaval/blob/main/docs/rbac-rules.md",
                "properties": {"tags": ["rbac", "security"]},
                }

    for rule_id, rule in rules_by_id.items():
        rule["properties"]["security-severity"] = _contextual_score_to_security_severity(
            max_score_by_rule[rule_id]
        )

    sarif_results = []
    for row in rows:
        f = row["raw"]
        binding = f["binding"]
        location_name = binding.get("namespace") or "cluster-scoped"
        cis_refs = [
            {"benchmark": r["benchmark"], "id": r.get("id")}
            for r in row["refs"]
        ]
        sarif_results.append({
            "ruleId": row["rule_id"],
            "level": row["level"],
            "message": {"text": row["message"]},
            "locations": [{
                "logicalLocations": [{
                    "name": f"{binding['kind']}/{binding['name']}",
                    "fullyQualifiedName": f"{location_name}/{binding['kind']}/{binding['name']}",
                }]
            }],
            "properties": {
                "contextual_score": f.get("contextual_score"),
                "severity": f.get("severity"),
                "cis_refs": cis_refs,
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Kaaval",
                    "informationUri": "https://github.com/kaaval/kaaval",
                    "rules": list(rules_by_id.values()),
                    }
                    },
            "results": sarif_results,
        }],
    }
    print(json.dumps(sarif, indent=2))


def _print_junit(result: dict) -> None:
    """JUnit XML — so GitLab CI and Jenkins render Kaaval findings in their
    native test-report panes. One testcase per finding (classname=rule_id),
    each reported as a <failure> so it surfaces the same way a failed test
    would; a clean scan emits a single passing testcase rather than an empty
    (and easily mistaken-for-broken) suite."""
    rows = _finding_rows(result)

    testsuite = ET.Element("testsuite", {
        "name": "kaaval.rbac",
        "tests": str(len(rows) or 1),
        "failures": str(len(rows)),
        "errors": "0",
    })

    if not rows:
        ET.SubElement(testsuite, "testcase", {
            "classname": "kaaval.rbac",
            "name": "no RBAC misconfigurations found",
        })
    else:
        for row in rows:
            binding = row["raw"]["binding"]
            location = binding.get("namespace") or "cluster-scoped"
            testcase = ET.SubElement(testsuite, "testcase", {
                "classname": f"kaaval.rbac.{row['rule_id']}",
                "name": row["title"],
            })
            failure = ET.SubElement(testcase, "failure", {
                "message": row["title"],
                "type": row["raw"].get("severity", "UNKNOWN"),
            })
            failure.text = (
                f"{row['message']}\n"
                f"via {binding['kind']} {binding['name']} ({location})"
            )

    ET.indent(ET.ElementTree(testsuite), space="  ")
    print(ET.tostring(testsuite, encoding="unicode", xml_declaration=True))


# PolicyReport (wgpolicyk8s.io/v1alpha2) — the Kubernetes Policy WG standard
# consumed by policy-reporter, Kyverno, Falco, and Trivy-operator. Kaaval only
# *emits* the documents; applying them to a cluster stays the caller's choice,
# keeping the scanner's read-only contract intact.

_SEVERITY_TO_POLICYREPORT = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


def _policyreport_result(f: dict) -> dict:
    binding = f["binding"]
    rem = f["remediation"]
    refs = "; ".join(
        f"{r['benchmark']}{' ' + r['id'] if r.get('id') else ''}"
        for r in rem["benchmark_refs"]
    )
    resource = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": binding["kind"],
        "name": binding["name"],
    }
    if binding.get("namespace"):
        resource["namespace"] = binding["namespace"]
    # properties values must be strings per the CRD schema
    properties = {
        "contextual_score": str(f.get("contextual_score", "")),
        "remediation": rem["action"],
        "why_it_matters": rem["why_it_matters"],
    }
    if refs:
        properties["benchmark_refs"] = refs
    return {
        "source": "Kaaval",
        "policy": f["rule_type"],
        "category": "rbac",
        "severity": _SEVERITY_TO_POLICYREPORT.get(f.get("severity", "UNKNOWN"), "info"),
        "result": "fail",
        "scored": True,
        "message": f["title"],
        "resources": [resource],
        "properties": properties,
    }


def _build_policy_reports(result: dict) -> list:
    """Group findings into one PolicyReport per namespace plus one
    ClusterPolicyReport for cluster-scoped findings."""
    by_namespace: dict = {}
    cluster_results: list = []
    for f in result["findings"]:
        ns = f["binding"].get("namespace")
        if ns:
            by_namespace.setdefault(ns, []).append(_policyreport_result(f))
        else:
            cluster_results.append(_policyreport_result(f))

    empty_summary = {"pass": 0, "fail": 0, "warn": 0, "error": 0, "skip": 0}
    reports = []
    for ns in sorted(by_namespace):
        results = by_namespace[ns]
        reports.append({
            "apiVersion": "wgpolicyk8s.io/v1alpha2",
            "kind": "PolicyReport",
            "metadata": {
                "name": "kaaval-rbac",
                "namespace": ns,
                "labels": {"app.kubernetes.io/managed-by": "kaaval"},
            },
            "summary": {**empty_summary, "fail": len(results)},
            "results": results,
        })
    # always emit the cluster report so a clean scan still produces an artifact
    reports.append({
        "apiVersion": "wgpolicyk8s.io/v1alpha2",
        "kind": "ClusterPolicyReport",
        "metadata": {
            "name": "kaaval-rbac",
            "labels": {"app.kubernetes.io/managed-by": "kaaval"},
        },
        "summary": {**empty_summary, "fail": len(cluster_results)},
        "results": cluster_results,
    })
    return reports


def _print_policyreport(result: dict) -> None:
    print(yaml.safe_dump_all(_build_policy_reports(result), sort_keys=False), end="")


def _apply_gate(findings: list, fail_on_score, fail_on_severity) -> int:
    breaches = []
    if fail_on_score is not None:
        breaches += [f for f in findings if f["contextual_score"] >= float(fail_on_score)]
    if fail_on_severity:
        threshold = fail_on_severity.upper()
        if threshold not in SEVERITY_ORDER:
            _fail_usage(f"--fail-on-severity must be one of {SEVERITY_ORDER[1:]}")
        rank = SEVERITY_ORDER.index(threshold)
        breaches += [f for f in findings if SEVERITY_ORDER.index(f.get("severity", "UNKNOWN")) >= rank]
    if breaches:
        unique = {id(f) for f in breaches}
        print(
            f"\nGATE FAILED: {len(unique)} finding(s) at or above threshold "
            f"(score>={fail_on_score if fail_on_score is not None else '-'}"
            f", severity>={fail_on_severity or '-'})",
            file=sys.stderr,
        )
        return 1
    return 0


# ── Entry point ───────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kaaval", description="Kaaval headless scanner for CI/CD pipelines."
    )
    parser.add_argument(
        "--version", action="version", version=f"kaaval {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Run a scan")
    scan_sub = scan.add_subparsers(dest="scan_type", required=True)

    rbac = scan_sub.add_parser("rbac", help="Scan RBAC objects for misconfigurations")
    source = rbac.add_mutually_exclusive_group()
    source.add_argument("--kubeconfig", help="Scan a live cluster via this kubeconfig")
    source.add_argument("--manifests", help="Scan RBAC YAML manifests in this file/directory (shift-left)")
    rbac.add_argument("--context-file", help="kaaval.yaml risk context (risk context as code)")
    rbac.add_argument("--fail-on-score", type=float, help="Exit 1 if any finding scores >= this")
    rbac.add_argument("--fail-on-severity", help="Exit 1 if any finding is at/above this severity")
    rbac.add_argument("--output", choices=["table", "json", "sarif", "policyreport", "junit"], default="table")

    args = parser.parse_args(argv)

    context = load_context(args.context_file)
    fail_on_score = args.fail_on_score if args.fail_on_score is not None else context.pop("_fail_on_score", None)
    fail_on_severity = args.fail_on_severity or context.pop("_fail_on_severity", None)
    context.pop("_fail_on_score", None)
    context.pop("_fail_on_severity", None)

    if args.manifests:
        graph = build_graph_from_manifests(args.manifests)
    else:
        graph = build_graph_from_cluster(args.kubeconfig)

    findings = evaluate_rbac_findings(graph, context)
    result = {
        "scan_type": "rbac",
        "mode": "manifests" if args.manifests else "live",
        "context": context,
        "total_bindings_checked": len(graph["role_bindings"]) + len(graph["cluster_role_bindings"]),
        "affected_count": len(findings),
        "severity_breakdown": _severity_breakdown(findings),
        "findings": findings,
    }

    if args.output == "json":
        print(json.dumps(result, indent=2))
    elif args.output == "sarif":
        _print_sarif(result)
    elif args.output == "policyreport":
        _print_policyreport(result)
    elif args.output == "junit":
        _print_junit(result)
    else:
        _print_table(result)

    return _apply_gate(findings, fail_on_score, fail_on_severity)


if __name__ == "__main__":
    sys.exit(main())
