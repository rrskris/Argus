"""
Unit tests for the RBAC rule engine (`evaluate_rbac_findings`) — pure-function
tests against synthetic graph dicts shaped exactly like
`K8sClient.get_rbac_graph_data()`'s output. No DB, no live cluster, no
network access needed, unlike the HTTP-level smoke test.
"""

from app.rbac_service import evaluate_rbac_findings

_CONTEXT = {"environment": "production", "data_classification": "internal", "exposure": "internal"}


def _cluster_role(name, rules):
    return {"name": name, "kind": "ClusterRole", "rules": rules}


def _cluster_role_binding(name, role_name, subjects):
    return {
        "name": name,
        "kind": "ClusterRoleBinding",
        "roleRef": {"kind": "ClusterRole", "name": role_name},
        "subjects": subjects,
    }


def test_wildcard_role_flagged():
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role("wide-open", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "wide-open-binding", "wide-open",
            [{"kind": "ServiceAccount", "name": "app", "namespace": "team-a"}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    rule_types = {f["rule_type"] for f in findings}
    assert "wildcard_permissions" in rule_types


def test_secrets_access_flagged():
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role("secret-reader", [
            {"verbs": ["get", "list"], "resources": ["secrets"], "api_groups": [""], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "secret-reader-binding", "secret-reader",
            [{"kind": "ServiceAccount", "name": "app", "namespace": "team-a"}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert any(f["rule_type"] == "broad_secrets_access" for f in findings)


def test_cluster_admin_bound_to_default_service_account_is_critical():
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role("cluster-admin", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "default-cluster-admin", "cluster-admin",
            [{"kind": "ServiceAccount", "name": "default", "namespace": "kube-system"}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    critical = [f for f in findings if f["rule_type"] == "cluster_admin_binding"]
    assert len(critical) == 1
    assert critical[0]["severity"] == "CRITICAL"


def test_scoped_role_with_narrow_subject_is_not_flagged_critical():
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role("cluster-admin", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "scoped-admin", "cluster-admin",
            [{"kind": "ServiceAccount", "name": "ci-deployer", "namespace": "ci"}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert not any(f["rule_type"] == "cluster_admin_binding" for f in findings)
    assert any(f["rule_type"] == "wildcard_permissions" for f in findings)


def test_findings_are_scored_and_sorted_by_contextual_score():
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [
            _cluster_role("cluster-admin", [
                {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
            ]),
            _cluster_role("pod-execer", [
                {"verbs": ["create"], "resources": ["pods/exec"], "api_groups": [""], "resource_names": []},
            ]),
        ],
        "cluster_role_bindings": [
            _cluster_role_binding(
                "default-cluster-admin", "cluster-admin",
                [{"kind": "Group", "name": "system:authenticated", "namespace": None}],
            ),
            _cluster_role_binding(
                "execer-binding", "pod-execer",
                [{"kind": "ServiceAccount", "name": "debug-tool", "namespace": "ops"}],
            ),
        ],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    scores = [f["contextual_score"] for f in findings]
    assert scores == sorted(scores, reverse=True)
    assert findings[0]["rule_type"] == "cluster_admin_binding"
    for f in findings:
        assert "score_factors" in f


def test_builtin_system_role_is_not_flagged():
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role("system:kube-controller-manager", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "system:kube-controller-manager", "system:kube-controller-manager",
            [{"kind": "User", "name": "system:kube-controller-manager", "namespace": None}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert findings == []


def test_cluster_admin_bound_to_builtin_group_is_not_flagged():
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role("cluster-admin", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "cluster-admin", "cluster-admin",
            [{"kind": "Group", "name": "system:masters", "namespace": None}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert findings == []


def test_cluster_admin_bound_to_real_service_account_is_still_flagged():
    """The allowlist must not suppress genuine misconfigurations — only
    Kubernetes-managed built-ins."""
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role("cluster-admin", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "risky-binding", "cluster-admin",
            [{"kind": "ServiceAccount", "name": "default", "namespace": "team-a"}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert any(f["rule_type"] == "cluster_admin_binding" for f in findings)


def test_cluster_admin_bound_to_all_authenticated_users_is_still_critical():
    """system:authenticated looks like a 'system:'-prefixed builtin but is a
    broad-audience group (anyone with a valid token), not a Kubernetes-managed
    control-plane identity -- the allowlist must never suppress this."""
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role("cluster-admin", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "dangerous-binding", "cluster-admin",
            [{"kind": "Group", "name": "system:authenticated", "namespace": None}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    critical = [f for f in findings if f["rule_type"] == "cluster_admin_binding"]
    assert len(critical) == 1
    assert critical[0]["severity"] == "CRITICAL"


def _single_rule_graph(role_name, rule, subject=None):
    """One ClusterRole with one rule, bound to one ordinary ServiceAccount."""
    subject = subject or {"kind": "ServiceAccount", "name": "app", "namespace": "team-a"}
    return {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role(role_name, [rule])],
        "cluster_role_bindings": [_cluster_role_binding(f"{role_name}-binding", role_name, [subject])],
    }


def test_escalation_verbs_flagged():
    graph = _single_rule_graph("escalator", {
        "verbs": ["escalate", "bind"], "resources": ["clusterroles"],
        "api_groups": ["rbac.authorization.k8s.io"], "resource_names": [],
    })

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    flagged = [f for f in findings if f["rule_type"] == "privilege_escalation_verbs"]
    assert len(flagged) == 1
    assert flagged[0]["severity"] == "HIGH"


def test_node_proxy_access_flagged():
    graph = _single_rule_graph("node-proxier", {
        "verbs": ["get", "create"], "resources": ["nodes/proxy"],
        "api_groups": [""], "resource_names": [],
    })

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert any(f["rule_type"] == "node_proxy_access" for f in findings)


def test_token_creation_flagged():
    graph = _single_rule_graph("token-minter", {
        "verbs": ["create"], "resources": ["serviceaccounts/token"],
        "api_groups": [""], "resource_names": [],
    })

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert any(f["rule_type"] == "token_creation" for f in findings)


def test_csr_approval_flagged():
    graph = _single_rule_graph("csr-approver", {
        "verbs": ["update"], "resources": ["certificatesigningrequests/approval"],
        "api_groups": ["certificates.k8s.io"], "resource_names": [],
    })

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert any(f["rule_type"] == "csr_approval" for f in findings)


def test_webhook_config_write_flagged():
    graph = _single_rule_graph("webhook-writer", {
        "verbs": ["create", "update"], "resources": ["mutatingwebhookconfigurations"],
        "api_groups": ["admissionregistration.k8s.io"], "resource_names": [],
    })

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert any(f["rule_type"] == "webhook_config_access" for f in findings)


def test_workload_creation_flagged_as_medium():
    graph = _single_rule_graph("deployer", {
        "verbs": ["create"], "resources": ["deployments"],
        "api_groups": ["apps"], "resource_names": [],
    })

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    flagged = [f for f in findings if f["rule_type"] == "workload_creation"]
    assert len(flagged) == 1
    assert flagged[0]["severity"] == "MEDIUM"


def test_pv_creation_flagged():
    graph = _single_rule_graph("pv-creator", {
        "verbs": ["create"], "resources": ["persistentvolumes"],
        "api_groups": [""], "resource_names": [],
    })

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert any(f["rule_type"] == "pv_creation" for f in findings)


def test_readonly_narrow_role_produces_no_rbac_risk_findings():
    """A narrow read-only ClusterRole produces no content-risk findings.
    The _single_rule_graph helper binds via ClusterRoleBinding to a namespaced SA,
    which correctly fires segmentation_violation — but the role itself carries
    no wildcard, secrets, exec, escalation, or other RBAC risk flags."""
    graph = _single_rule_graph("viewer", {
        "verbs": ["get", "list", "watch"], "resources": ["configmaps", "services"],
        "api_groups": [""], "resource_names": [],
    })

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    # Segmentation violation fires (correct — namespaced SA bound cluster-wide).
    # No other RBAC content risk should appear.
    non_seg = [f for f in findings if f["rule_type"] != "segmentation_violation"]
    assert non_seg == []


def test_user_created_binding_to_system_masters_is_flagged():
    """CIS 5.1.7: system:masters bypasses RBAC entirely. Only the stock
    `cluster-admin` ClusterRoleBinding is legitimate — any other binding to
    the group must NOT be suppressed by the builtin allowlist."""
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role("cluster-admin", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "sneaky-masters", "cluster-admin",
            [{"kind": "Group", "name": "system:masters", "namespace": None}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    critical = [f for f in findings if f["rule_type"] == "cluster_admin_binding"]
    assert len(critical) == 1
    assert critical[0]["severity"] == "CRITICAL"


def test_findings_carry_remediation():
    graph = _single_rule_graph("secret-reader", {
        "verbs": ["get", "list"], "resources": ["secrets"],
        "api_groups": [""], "resource_names": [],
    })

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert findings
    remediation = findings[0]["remediation"]
    assert remediation["action"]
    assert remediation["why_it_matters"]
    assert any(ref.get("id") == "5.1.2" for ref in remediation["benchmark_refs"])


def test_no_matching_role_for_binding_is_skipped_without_error():
    graph = {
        "roles": [], "role_bindings": [], "cluster_roles": [],
        "cluster_role_bindings": [_cluster_role_binding(
            "dangling-binding", "does-not-exist",
            [{"kind": "ServiceAccount", "name": "app", "namespace": "team-a"}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert findings == []


# ── Segmentation-violation rule (issue #49) ───────────────────────────────────

def _role_binding(name, role_name, subjects, namespace="team-a"):
    return {
        "name": name,
        "kind": "RoleBinding",
        "namespace": namespace,
        "roleRef": {"kind": "ClusterRole", "name": role_name},
        "subjects": subjects,
    }


def test_namespaced_sa_cluster_role_binding_is_segmentation_violation():
    """A ServiceAccount from namespace 'team-a' bound cluster-wide via
    ClusterRoleBinding violates micro-segmentation."""
    graph = {
        "roles": [],
        "role_bindings": [],
        "cluster_roles": [_cluster_role("pod-reader", [
            {"verbs": ["get", "list", "watch"], "resources": ["pods"],
             "api_groups": [""], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "team-a-cluster-reader", "pod-reader",
            [{"kind": "ServiceAccount", "name": "monitor", "namespace": "team-a"}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    seg = [f for f in findings if f["rule_type"] == "segmentation_violation"]
    assert len(seg) == 1
    assert seg[0]["severity"] == "HIGH"
    assert "team-a" in seg[0]["description"]
    assert "cluster scope" in seg[0]["description"]


def test_cluster_sa_cluster_role_binding_is_not_segmentation_violation():
    """A ServiceAccount with no namespace (non-namespaced subject) bound
    cluster-wide is normal — only namespaced SAs trigger the rule."""
    graph = {
        "roles": [],
        "role_bindings": [],
        "cluster_roles": [_cluster_role("pod-reader", [
            {"verbs": ["get"], "resources": ["pods"],
             "api_groups": [""], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "user-reader", "pod-reader",
            [{"kind": "User", "name": "alice", "namespace": None}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert not any(f["rule_type"] == "segmentation_violation" for f in findings)


def test_cross_namespace_role_binding_is_segmentation_violation():
    """A RoleBinding in namespace 'team-b' that grants access to a ServiceAccount
    from 'team-a' is cross-namespace reach."""
    graph = {
        "roles": [],
        "cluster_roles": [_cluster_role("configmap-reader", [
            {"verbs": ["get", "list"], "resources": ["configmaps"],
             "api_groups": [""], "resource_names": []},
        ])],
        "cluster_role_bindings": [],
        "role_bindings": [_role_binding(
            "cross-ns-binding", "configmap-reader",
            [{"kind": "ServiceAccount", "name": "reader", "namespace": "team-a"}],
            namespace="team-b",
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    seg = [f for f in findings if f["rule_type"] == "segmentation_violation"]
    assert len(seg) == 1
    assert seg[0]["severity"] == "HIGH"
    assert "team-a" in seg[0]["description"]
    assert "team-b" in seg[0]["description"]


def test_same_namespace_role_binding_is_not_segmentation_violation():
    """A RoleBinding in 'team-a' granting a ServiceAccount from 'team-a'
    is contained — no cross-namespace reach."""
    graph = {
        "roles": [],
        "cluster_roles": [_cluster_role("configmap-reader", [
            {"verbs": ["get", "list"], "resources": ["configmaps"],
             "api_groups": [""], "resource_names": []},
        ])],
        "cluster_role_bindings": [],
        "role_bindings": [_role_binding(
            "same-ns-binding", "configmap-reader",
            [{"kind": "ServiceAccount", "name": "reader", "namespace": "team-a"}],
            namespace="team-a",
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert not any(f["rule_type"] == "segmentation_violation" for f in findings)


def test_segmentation_violation_carries_remediation():
    """segmentation_violation findings must carry a remediation block with
    action, why_it_matters, and benchmark_refs."""
    graph = {
        "roles": [],
        "role_bindings": [],
        "cluster_roles": [_cluster_role("pod-reader", [
            {"verbs": ["get", "list"], "resources": ["pods"],
             "api_groups": [""], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "team-a-cluster-reader", "pod-reader",
            [{"kind": "ServiceAccount", "name": "monitor", "namespace": "team-a"}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    seg = [f for f in findings if f["rule_type"] == "segmentation_violation"]
    assert seg
    remediation = seg[0]["remediation"]
    assert remediation["action"]
    assert remediation["why_it_matters"]
    assert remediation["benchmark_refs"]


def test_segmentation_violation_stacks_with_other_risks():
    """A namespaced SA bound cluster-wide via a wildcard ClusterRole should
    produce BOTH wildcard_permissions AND segmentation_violation findings."""
    graph = {
        "roles": [],
        "role_bindings": [],
        "cluster_roles": [_cluster_role("wide-open", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "team-a-wide-open", "wide-open",
            [{"kind": "ServiceAccount", "name": "app", "namespace": "team-a"}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    rule_types = {f["rule_type"] for f in findings}
    assert "wildcard_permissions" in rule_types
    assert "segmentation_violation" in rule_types

# ── token_automount (CIS 5.1.6) ──────────────────────────────────────────────

_EMPTY_RBAC = {"roles": [], "cluster_roles": [], "role_bindings": [], "cluster_role_bindings": []}


def _sa(name, namespace="team-a", **kwargs):
    sa = {"name": name, "namespace": namespace, "kind": "ServiceAccount"}
    sa.update(kwargs)
    return sa


def _pod(name, sa_name, automount, namespace="team-a"):
    return {
        "name": name, "namespace": namespace, "kind": "Pod",
        "service_account_name": sa_name,
        "automountServiceAccountToken": automount,
    }


def _automount_findings(graph):
    return [f for f in evaluate_rbac_findings(graph, _CONTEXT) if f["rule_type"] == "token_automount"]


def test_automount_absent_field_fires():
    # Field entirely absent → Kubernetes defaults to true → must fire.
    graph = {**_EMPTY_RBAC, "service_accounts": [_sa("app")], "pods": []}
    findings = _automount_findings(graph)
    assert len(findings) == 1
    assert findings[0]["severity"] == "LOW"
    assert findings[0]["service_account"] == {"name": "app", "namespace": "team-a"}


def test_automount_null_value_fires():
    # `automountServiceAccountToken:` with no value parses as None → still unset → fires.
    graph = {**_EMPTY_RBAC, "pods": [],
             "service_accounts": [_sa("app", automountServiceAccountToken=None)]}
    assert len(_automount_findings(graph)) == 1


def test_automount_explicit_true_fires():
    graph = {**_EMPTY_RBAC, "pods": [],
             "service_accounts": [_sa("app", automountServiceAccountToken=True)]}
    assert len(_automount_findings(graph)) == 1


def test_automount_explicit_false_does_not_fire():
    graph = {**_EMPTY_RBAC, "pods": [],
             "service_accounts": [_sa("app", automountServiceAccountToken=False)]}
    assert _automount_findings(graph) == []


def test_automount_default_sa_scores_medium():
    graph = {**_EMPTY_RBAC, "pods": [], "service_accounts": [_sa("default")]}
    findings = _automount_findings(graph)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["remediation"]["benchmark_refs"][0]["id"] == "5.1.6"


def test_automount_pod_override_of_opted_out_sa_fires():
    # Pod spec wins over the SA object: true on the pod re-exposes the token.
    graph = {**_EMPTY_RBAC,
             "service_accounts": [_sa("locked", automountServiceAccountToken=False)],
             "pods": [_pod("sneaky", "locked", True)]}
    findings = _automount_findings(graph)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["workload"] == {"kind": "Pod", "name": "sneaky", "namespace": "team-a"}


def test_automount_pod_explicit_false_does_not_fire():
    graph = {**_EMPTY_RBAC,
             "service_accounts": [_sa("locked", automountServiceAccountToken=False)],
             "pods": [_pod("quiet", "locked", False)]}
    assert _automount_findings(graph) == []


def test_automount_pod_inheriting_sa_not_double_reported():
    # SA fires once; a pod that merely inherits (unset) must not add a second finding.
    graph = {**_EMPTY_RBAC,
             "service_accounts": [_sa("app", automountServiceAccountToken=True)],
             "pods": [_pod("worker", "app", None)]}
    assert len(_automount_findings(graph)) == 1


def test_automount_graph_without_new_keys_is_backward_compatible():
    # Graphs from older collectors have no service_accounts/pods keys — no crash, no findings.
    assert _automount_findings(dict(_EMPTY_RBAC)) == []


def test_automount_workload_template_override_fires_with_kind():
    # A Deployment's pod template setting true over an opted-out SA must fire,
    # and the finding must carry the workload's real kind.
    graph = {**_EMPTY_RBAC,
             "service_accounts": [_sa("locked", automountServiceAccountToken=False)],
             "pods": [{"name": "web", "namespace": "team-a", "kind": "Deployment",
                       "service_account_name": "locked",
                       "automountServiceAccountToken": True}]}
    findings = _automount_findings(graph)
    assert len(findings) == 1
    assert findings[0]["workload"]["kind"] == "Deployment"
    assert findings[0]["title"] == "Token Automount via Deployment 'web'"
