# RBAC rule catalog

Every rule the RBAC scanner (`control-plane/app/rbac_service.py`) evaluates,
what triggers it, how it's scored, and what it maps to. Findings are produced
per **(risky role, binding)** pair — a risky role with no binding produces no
finding, because nobody holds the permission yet; the same role bound twice
produces two findings, because the fix is two binding reviews.

All severities below are the **base** severity; the final ranking is the
[Contextual Risk Score](contextual-risk-score.md) (base × environment × data
classification × compliance scope × exposure). Benchmark citations are to the
**CIS Kubernetes Benchmark v1.12.0**.

## Rules

| `rule_type` | Trigger (any rule in the Role/ClusterRole) | Base severity | Maps to |
|---|---|---|---|
| `wildcard_permissions` | `*` in verbs or resources | HIGH (ClusterRole) / MEDIUM (Role) | CIS 5.1.3 |
| `broad_secrets_access` | `secrets` + any of get/list/watch | HIGH (ClusterRole) / MEDIUM (Role) | CIS 5.1.2 |
| `exec_attach_grant` | `pods/exec`, `pods/attach`, or `pods/portforward` + create/get | MEDIUM | RBAC Good Practices, OWASP K03 (no CIS 5.1 control exists) |
| `privilege_escalation_verbs` | any of `escalate`, `bind`, `impersonate` | HIGH (ClusterRole) / MEDIUM (Role) | CIS 5.1.8 |
| `token_automount` | ServiceAccount with `automountServiceAccountToken` unset/null/true (`default` SA → MEDIUM, others LOW), or a workload (Pod, or the pod template of a Deployment/StatefulSet/DaemonSet/ReplicaSet/Job/CronJob) setting it `true` over an SA that opted out (MEDIUM) | MEDIUM / LOW | CIS 5.1.6 |
| `token_creation` | `serviceaccounts/token` + create | HIGH (ClusterRole) / MEDIUM (Role) | CIS 5.1.13 |
| `workload_creation` | create on pods/deployments/daemonsets/statefulsets/replicasets/jobs/cronjobs | MEDIUM | CIS 5.1.4 |
| `node_proxy_access` | `nodes/proxy` (ClusterRole only) | HIGH | CIS 5.1.10 |
| `csr_approval` | `certificatesigningrequests/approval` + update/patch (ClusterRole only) | HIGH | CIS 5.1.11 |
| `webhook_config_access` | write verbs on mutating/validating webhook configurations (ClusterRole only) | HIGH | CIS 5.1.12 |
| `pv_creation` | `persistentvolumes` + create (ClusterRole only) | HIGH | CIS 5.1.9 |
| `cluster_admin_binding` | cluster-admin (or wildcard-equivalent role) bound to a **broad identity** | CRITICAL | CIS 5.1.1 (+5.1.7 when the subject is `system:masters`) |
| `segmentation_violation` | a namespaced `ServiceAccount` bound cluster-wide via `ClusterRoleBinding`, or a `RoleBinding` granting a SA from a different namespace (cross-namespace reach) | HIGH | NIST SP 800-207A (Zero Trust micro-segmentation), Kubernetes RBAC Good Practices (no CIS 5.1 control covers namespace isolation directly) |

Notes on the less obvious ones:

- **`exec_attach_grant`** — exec into a pod is code execution inside the
  container, with the pod's ServiceAccount token and mounted secrets in
  reach. There is deliberately no invented CIS ID here: no 5.1 control covers
  it, so the citation is the Kubernetes RBAC Good Practices document and
  OWASP Kubernetes Top 10 K03.
- **`privilege_escalation_verbs`** — `escalate` lets the holder edit roles to
  exceed their own grants, `bind` lets them bind roles they don't hold,
  `impersonate` lets them act as another identity. Each is a full
  privilege-escalation primitive on its own.
- **`workload_creation`** — creating a pod implicitly reaches every Secret,
  ConfigMap, and ServiceAccount that can be mounted in that namespace.
  MEDIUM because it's also the most legitimately-held permission (CI
  deployers, controllers); the contextual score, not the base severity, is
  what should decide urgency here.
- **`node_proxy_access`** — `nodes/proxy` is kubelet API access: command
  execution on any pod on the node, **bypassing API-server audit logging and
  admission control**. One of the least-known, highest-impact grants.
- **Cluster-scoped-only rules** (`node_proxy_access`, `csr_approval`,
  `webhook_config_access`, `pv_creation`) target cluster-scoped resources; a
  namespaced Role granting them is inert, so only ClusterRoles are evaluated
  — this avoids flagging permissions that cannot actually be used.
- **`cluster_admin_binding`** — "broad identity" means: the `default`
  ServiceAccount (every pod in the namespace that doesn't set one), or the
  groups `system:authenticated` (every valid token), `system:unauthenticated`
  (no token at all), `system:masters` (bypasses RBAC entirely).
  "Wildcard-equivalent" means a role with `*` verbs+resources+apiGroups, not
  just the literal `cluster-admin` name.
- **`segmentation_violation`** — fires when a namespaced `ServiceAccount` is
  lifted to cluster scope via a `ClusterRoleBinding`, or when a `RoleBinding`
  grants a SA from a different namespace. Both patterns break the Zero Trust
  micro-segmentation tenet: workload identities should not cross the namespace
  boundary. Note that many legitimate cluster agents (Prometheus, ingress
  controllers, cert-manager, Flux, Argo CD) bind a namespaced SA cluster-wide
  by design — this is an **expected cluster-agent SA** pattern. When you confirm
  a finding is intentional, document it in your access-review log and let the
  Contextual Risk Score (environment + data classification) determine urgency
  rather than suppressing the rule. The base severity of HIGH exists to surface
  the pattern for review, not to mandate immediate remediation.

## Suppression rules (noise control, and its limits)

A stock cluster ships dozens of powerful built-in roles. Flagging them is
true-positive-but-useless noise that drowns real misconfigurations, so the
scanner suppresses:

1. **Built-in roles**: any Role/ClusterRole named `system:*` or `kubeadm:*`.
2. **Built-in subjects**: bindings where *every* subject is a `system:*` /
   `kubeadm:*` Group or User — **except** the broad-audience groups below.
3. **The stock `cluster-admin` ClusterRoleBinding** (name `cluster-admin`,
   role `cluster-admin`, subject group `system:masters`) — present in every
   cluster since bootstrap.

Never suppressed, deliberately:

- **`system:authenticated` / `system:unauthenticated`** — they look like
  `system:` built-ins but are broad-audience groups. Binding anything risky
  to them is a genuine misconfiguration.
- **`system:masters`** in any binding *other than* the stock one (CIS 5.1.7).
  Membership in this group bypasses RBAC authorization entirely; a
  user-created binding to it signals someone is provisioning `system:masters`
  credentials, which is exactly what 5.1.7 exists to catch.

## Expected findings that are working as intended

- **Storage provisioners** (kind's `local-path-provisioner`, CSI external
  provisioners) legitimately hold `persistentvolumes` create and workload
  permissions — they will appear under `pv_creation`/`workload_creation`.
  That's correct: the grant is real and worth knowing about; the contextual
  score ranks it below actual incidents. If it's expected in your platform,
  that's what the audit note is for.
- **CI/CD deployer ServiceAccounts** will appear under `workload_creation`.
  Same reasoning — the finding documents the blast radius of a compromised
  pipeline credential.

## Verification pedigree

The rule set is covered by pure-function unit tests
(`control-plane/tests/test_rbac_service.py`) and was live-verified against a
kind cluster with 11 planted fixtures: all risky fixtures detected with
correct CIS references, a deliberately-safe role produced zero findings, the
stock `cluster-admin` binding stayed suppressed while a user-created
`system:masters` binding ranked #1 CRITICAL.
