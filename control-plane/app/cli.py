"""
Argus CLI — headless scanning for CI/CD pipelines.

Runs the same pure rule engine and Contextual Risk Score the server uses,
with no database, auth, or running control plane:

    # live cluster (CI service-account kubeconfig)
    python -m app.cli scan rbac --kubeconfig ./ci-kubeconfig

    # static manifests, before they ever reach a cluster (shift-left)
    python -m app.cli scan rbac --manifests ./k8s/

    # gate the pipeline on contextually scored risk
    python -m app.cli scan rbac --manifests ./k8s/ \
        --context-file argus.yaml --fail-on-score 20 --output json

The risk context lives in a versioned file in the app repo (argus.yaml):

    environment: production          # production | staging | dev
    data_classification: pii         # public | internal | pii | financial | phi
    compliance_scope: [PCI-DSS]
    exposure: internet-facing        # internet-facing | internal
    fail_on_score: 20                # optional; CLI flags override
    fail_on_severity: HIGH           # optional

That is the point of gating on Argus instead of a flat severity threshold:
the same wildcard ClusterRole that hard-fails a production/PCI pipeline can
pass with a warning in dev, because the context says so.

Exit codes: 0 clean/below threshold, 1 threshold breached, 2 usage error.
"""

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

from .rbac_service import evaluate_rbac_findings
from .scoring import (
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


# ── Risk context ───────────────────────────────────────────────────────────────

def load_context(path: str | None) -> dict:
    """Load and validate the risk-context file; defaults + warning if absent."""
    if not path:
        print(
            "warning: no --context-file given — scoring with defaults "
            f"({_DEFAULT_CONTEXT['environment']}/{_DEFAULT_CONTEXT['data_classification']}/"
            f"{_DEFAULT_CONTEXT['exposure']}, no compliance scope). "
            "Commit an argus.yaml for context-aware gating.",
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
    if not root.exists():
        _fail_usage(f"manifests path not found: {path_str}")

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
    print(f"Argus RBAC scan — {result['total_bindings_checked']} bindings checked, "
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


def _print_sarif(result: dict) -> None:
    rows = _finding_rows(result)

    rules_by_id = {}
    for row in rows:
        if row["rule_id"] not in rules_by_id:
            rules_by_id[row["rule_id"]] = {
                "id": row["rule_id"],
                "name": row["rule_id"],
                "shortDescription": {"text": row["title"]},
                "helpUri": "https://github.com/rrskris/Argus",
                "properties": {"tags": ["rbac", "security"]},
            }

    sarif_results = []
    for row in rows:
        f = row["raw"]
        binding = f["binding"]
        location_name = binding.get("namespace") or "cluster-scoped"
        taxa = [
            {"toolComponent": {"name": r["benchmark"]}, "id": r.get("id") or r["benchmark"]}
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
            },
            **({"taxa": taxa} if taxa else {}),
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Argus",
                    "informationUri": "https://github.com/rrskris/Argus",
                    "rules": list(rules_by_id.values()),
                }
            },
            "results": sarif_results,
        }],
    }
    print(json.dumps(sarif, indent=2))

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
        prog="argus", description="Argus headless scanner for CI/CD pipelines."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Run a scan")
    scan_sub = scan.add_subparsers(dest="scan_type", required=True)

    rbac = scan_sub.add_parser("rbac", help="Scan RBAC objects for misconfigurations")
    source = rbac.add_mutually_exclusive_group()
    source.add_argument("--kubeconfig", help="Scan a live cluster via this kubeconfig")
    source.add_argument("--manifests", help="Scan RBAC YAML manifests in this file/directory (shift-left)")
    rbac.add_argument("--context-file", help="argus.yaml risk context (risk context as code)")
    rbac.add_argument("--fail-on-score", type=float, help="Exit 1 if any finding scores >= this")
    rbac.add_argument("--fail-on-severity", help="Exit 1 if any finding is at/above this severity")
    rbac.add_argument("--output", choices=["table", "json", "sarif"], default="table")

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
    else:
      _print_table(result)

    return _apply_gate(findings, fail_on_score, fail_on_severity)


if __name__ == "__main__":
    sys.exit(main())
