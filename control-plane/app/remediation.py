"""
Shared remediation builder — turns any Kaaval finding (CVE or RBAC) into the
explainable "what to do + why it matters + what it maps to" output that is
the product's actual differentiator. Lives next to scoring.py because it is
the same idea applied to the other half of the finding: scoring.py explains
the rank, this module explains the fix.

Benchmark references cite CIS Kubernetes Benchmark v1.12.0 (verified 2026-07)
by exact control ID. Rules with no CIS control (e.g. exec/attach grants) cite
the Kubernetes RBAC Good Practices doc and OWASP Kubernetes Top 10 instead —
a wrong compliance citation is worse than none.
"""

CIS_BENCHMARK = "CIS Kubernetes Benchmark v1.12.0"
_RBAC_GOOD_PRACTICES_URL = "https://kubernetes.io/docs/concepts/security/rbac-good-practices/"

# CIS v1.12.0 section 5.1 (RBAC and Service Accounts) controls, keyed by the
# rule_type emitted by rbac_service.evaluate_rbac_findings().
_CIS_REFS = {
    "wildcard_permissions": [
        {"benchmark": CIS_BENCHMARK, "id": "5.1.3", "title": "Minimize wildcard use in Roles and ClusterRoles"},
    ],
    "broad_secrets_access": [
        {"benchmark": CIS_BENCHMARK, "id": "5.1.2", "title": "Minimize access to secrets"},
    ],
    "cluster_admin_binding": [
        {"benchmark": CIS_BENCHMARK, "id": "5.1.1", "title": "Ensure that the cluster-admin role is only used where required"},
    ],
    "privilege_escalation_verbs": [
        {"benchmark": CIS_BENCHMARK, "id": "5.1.8", "title": "Limit use of the Bind, Impersonate, and Escalate permissions"},
    ],
    "node_proxy_access": [
        {"benchmark": CIS_BENCHMARK, "id": "5.1.10", "title": "Minimize access to the proxy subresource of nodes"},
    ],
    "token_creation": [
        {"benchmark": CIS_BENCHMARK, "id": "5.1.13", "title": "Minimize access to the service account token creation"},
    ],
    "csr_approval": [
        {"benchmark": CIS_BENCHMARK, "id": "5.1.11", "title": "Minimize access to the approval subresource of certificatesigningrequests objects"},
    ],
    "webhook_config_access": [
        {"benchmark": CIS_BENCHMARK, "id": "5.1.12", "title": "Minimize access to webhook configuration objects"},
    ],
    "workload_creation": [
        {"benchmark": CIS_BENCHMARK, "id": "5.1.4", "title": "Minimize access to create pods"},
    ],
    "token_automount": [
        {"benchmark": CIS_BENCHMARK, "id": "5.1.6", "title": "Ensure that Service Account Tokens are only mounted where necessary"},
    ],
    "pv_creation": [
        {"benchmark": CIS_BENCHMARK, "id": "5.1.9", "title": "Minimize access to create persistent volumes"},
    ],
    # exec/attach has NO CIS 5.1 control — cite the primary sources instead.
    "exec_attach_grant": [
        {"benchmark": "Kubernetes RBAC Good Practices", "id": None,
         "title": f"Least privilege for pod exec/attach — {_RBAC_GOOD_PRACTICES_URL}"},
        {"benchmark": "OWASP Kubernetes Top 10", "id": "K03",
         "title": "Overly permissive RBAC configurations"},
    ],
    # Segmentation violation: namespaced identity reaching cluster/cross-namespace scope.
    # There is no CIS 5.1 control that directly covers segmentation — CIS 5.1.5 is
    # about default SA token automount, not namespace isolation.  NIST SP 800-207A
    # is the right primary reference (Zero Trust micro-segmentation); it uses no
    # MS-n control-numbering scheme, so id is null.  The Kubernetes RBAC Good
    # Practices doc has an explicit namespace-isolation section.
    "segmentation_violation": [
        {"benchmark": "NIST SP 800-207A", "id": None,
         "title": "Zero Trust micro-segmentation — workload identities must not cross namespace boundaries"},
        {"benchmark": "Kubernetes RBAC Good Practices", "id": None,
         "title": f"Namespace isolation — {_RBAC_GOOD_PRACTICES_URL}"},
    ],
}

# Group subjects with an extra CIS control beyond the rule's own mapping.
_SYSTEM_MASTERS_REF = {
    "benchmark": CIS_BENCHMARK, "id": "5.1.7", "title": "Avoid use of system:masters group",
}

# Per-rule_type fix instructions, with the concrete command to start from.
_RBAC_ACTIONS = {
    "wildcard_permissions": (
        "Replace wildcard verbs/resources in {role} with the explicit list the "
        "workload actually needs. Review with: kubectl get {role_arg} -o yaml"
    ),
    "broad_secrets_access": (
        "Drop get/list/watch on secrets from {role}, or constrain it with "
        "resourceNames to the specific Secrets required. list/watch return full "
        "secret contents, not just names."
    ),
    "exec_attach_grant": (
        "Remove pods/exec, pods/attach, and pods/portforward from {role}; grant "
        "interactive access through an audited break-glass role instead of a "
        "standing permission."
    ),
    "cluster_admin_binding": (
        "Delete the binding ({binding_cmd}) and create a narrowly scoped "
        "Role/RoleBinding for what the subject actually does."
    ),
    "privilege_escalation_verbs": (
        "Remove the escalate/bind/impersonate verbs from {role} — each one lets "
        "the holder mint permissions they were never granted."
    ),
    "node_proxy_access": (
        "Remove nodes/proxy from {role}. It allows direct kubelet API access, "
        "which bypasses API-server audit logging and admission control."
    ),
    "token_creation": (
        "Remove create on serviceaccounts/token from {role}; issue tokens through "
        "your workload-identity mechanism instead of ad-hoc TokenRequests."
    ),
    "csr_approval": (
        "Remove update/patch on certificatesigningrequests/approval from {role}. "
        "CSR approval rights allow issuing client certificates for arbitrary "
        "identities, including system components."
    ),
    "webhook_config_access": (
        "Remove write access to mutating/validating webhook configurations from "
        "{role} — controlling admission webhooks is equivalent to controlling "
        "every object admitted to the cluster."
    ),
    "workload_creation": (
        "Restrict create on workload resources in {role} to the deployment "
        "pipeline's ServiceAccount. Creating pods implicitly reaches every "
        "Secret and ServiceAccount mountable in the namespace."
    ),
    "pv_creation": (
        "Remove create on persistentvolumes from {role}; provision storage via "
        "PersistentVolumeClaims and StorageClasses. Direct PV creation enables "
        "hostPath mounts onto node filesystems."
    ),
    "token_automount": (
        "Set automountServiceAccountToken: false on the ServiceAccount (and on "
        "pod specs that do not call the Kubernetes API). Create a dedicated "
        "ServiceAccount with automount enabled only for workloads that need it."
    ),
    "segmentation_violation": (
        "Replace the ClusterRoleBinding with a namespaced RoleBinding scoped to "
        "the ServiceAccount's own namespace, or create a namespace-scoped Role "
        "with only the permissions the workload actually needs. "
        "Remove the binding with: {binding_cmd}"
    ),
}

# Framework → control citation, split by finding domain: CVE findings map to
# patch/vulnerability-management controls, RBAC findings to access-control
# controls. A starting point, not a compliance-mapping engine.
_CVE_COMPLIANCE_NOTES = {
    "PCI-DSS": "PCI-DSS Req 6.2 — apply security patches for known vulnerabilities.",
    "HIPAA": "HIPAA Security Rule 164.308(a)(5) — protect against known vulnerabilities.",
    "SOC2": "SOC 2 CC7.1 — identify and remediate vulnerabilities in a timely manner.",
}
_RBAC_COMPLIANCE_NOTES = {
    "PCI-DSS": "PCI-DSS Req 7 — restrict access to system components to least privilege / need to know.",
    "HIPAA": "HIPAA Security Rule 164.308(a)(4) — information access management, minimum necessary access.",
    "SOC2": "SOC 2 CC6.3 — provision and modify access based on roles and least privilege.",
}


def _context_reasons(factors: dict) -> list[str]:
    """Reasons derived from score factors that actually raised the score (weight > 1.0)."""
    reasons = []
    env = factors.get("environment", {})
    if env.get("weight", 1.0) > 1.0:
        reasons.append(f"this is a {env.get('value')} environment")
    data_class = factors.get("data_classification", {})
    if data_class.get("weight", 1.0) > 1.0:
        reasons.append(f"it handles {data_class.get('value')} data")
    exposure = factors.get("exposure", {})
    if exposure.get("weight", 1.0) > 1.0:
        reasons.append(f"it's {exposure.get('value')}")
    compliance_scope = factors.get("compliance_scope", {}).get("value") or []
    if compliance_scope:
        reasons.append(f"it's in scope for {', '.join(compliance_scope)}")
    return reasons


def _why_it_matters(finding: dict, inherent_risk: str = "") -> str:
    reasons = _context_reasons(finding.get("score_factors") or {})
    score = finding.get("contextual_score")
    if reasons:
        ranked = (
            f"Ranked {score} because {', and '.join(reasons)} — "
            "higher than raw severity alone would suggest."
        )
    else:
        ranked = (
            f"Ranked {score}, using baseline severity only — no elevated risk "
            "context (environment, data classification, exposure) is set for this cluster. "
            "Configure it under Settings for sharper prioritization."
        )
    return f"{inherent_risk} {ranked}".strip()


def _compliance_note(compliance_scope: list, notes_table: dict):
    if not compliance_scope:
        return None
    notes = [notes_table.get(fw) for fw in compliance_scope]
    return " ".join(n for n in notes if n) or None


def _build_cve_remediation(finding: dict) -> dict:
    fixed_in = finding.get("fixed_in")
    fixed_version = fixed_in[0] if isinstance(fixed_in, list) and fixed_in else fixed_in
    affected = finding.get("affected") or []
    component = affected[0].get("component") if affected else "the affected component"
    if fixed_version:
        action = f"Upgrade {component} to {fixed_version} or later."
    else:
        action = f"No fixed version published yet for {component} — track this CVE for an update."

    compliance_scope = (finding.get("score_factors") or {}).get("compliance_scope", {}).get("value") or []
    cve_id = finding.get("cve_id", "this CVE")
    audit_note = (
        f"Document remediation of {cve_id} as evidence for "
        f"{', '.join(compliance_scope)} audit scope." if compliance_scope
        else f"Document remediation of {cve_id} in your change log."
    )

    return {
        "action": action,
        "why_it_matters": _why_it_matters(finding),
        "compliance_note": _compliance_note(compliance_scope, _CVE_COMPLIANCE_NOTES),
        "audit_note": audit_note,
        "benchmark_refs": [],
    }


def _build_rbac_remediation(finding: dict) -> dict:
    rule_type = finding.get("rule_type", "")
    role = finding.get("role") or {}
    binding = finding.get("binding") or {}
    if rule_type == "token_automount":
        # These findings target a ServiceAccount / Pod, not a Role/Binding.
        sa = finding.get("service_account") or {}
        workload = finding.get("workload")
        role_desc = (
            f"{workload.get('kind', 'Pod')} '{workload.get('name', '?')}'"
            if workload else f"ServiceAccount '{sa.get('name', '?')}'"
        )
        if (workload or sa).get("namespace"):
            role_desc += f" in namespace '{(workload or sa)['namespace']}'"
    else:
        role_desc = f"{role.get('kind', 'Role')} '{role.get('name', '?')}'"
    role_arg = f"{(role.get('kind') or 'role').lower()} {role.get('name', '')}".strip()

    binding_cmd = f"kubectl delete {(binding.get('kind') or 'rolebinding').lower()} {binding.get('name', '')}"
    if binding.get("namespace"):
        binding_cmd += f" -n {binding['namespace']}"

    action_template = _RBAC_ACTIONS.get(
        rule_type, "Review and narrow {role} to least privilege."
    )
    action = action_template.format(role=role_desc, role_arg=role_arg, binding_cmd=binding_cmd)

    benchmark_refs = list(_CIS_REFS.get(rule_type, []))
    subjects = finding.get("subjects") or []
    if any(s.get("kind") == "Group" and s.get("name") == "system:masters" for s in subjects):
        benchmark_refs.append(_SYSTEM_MASTERS_REF)

    compliance_scope = (finding.get("score_factors") or {}).get("compliance_scope", {}).get("value") or []
    change_desc = (
        f"the automount opt-out for {role_desc}" if rule_type == "token_automount"
        else f"the narrowing of {role_desc}"
    )
    audit_note = (
        f"Record {change_desc} as access-review evidence for "
        f"{', '.join(compliance_scope)} audit scope." if compliance_scope
        else f"Record {change_desc} in your access-review log."
    )

    return {
        "action": action,
        "why_it_matters": _why_it_matters(finding, inherent_risk=finding.get("description", "")),
        "compliance_note": _compliance_note(compliance_scope, _RBAC_COMPLIANCE_NOTES),
        "audit_note": audit_note,
        "benchmark_refs": benchmark_refs,
    }


def build_remediation(finding: dict) -> dict:
    """
    Build the remediation object for one finding, from either finding shape:
    RBAC findings carry `rule_type`; CVE findings carry `cve_id`.
    """
    if "rule_type" in finding:
        return _build_rbac_remediation(finding)
    return _build_cve_remediation(finding)
