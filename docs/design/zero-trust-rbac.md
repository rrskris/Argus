# Design: Zero-Trust RBAC posture analysis

> Status: **design / RFC** — no engine code yet. This document is the spec the
> first implementation (the Effective Access Graph,
> [#47](https://github.com/kaaval/kaaval/issues/47)) builds against.
> Comments welcome on the issue or in Discussions.

## Why this exists

Kaaval today does **role-centric dangerous-permission detection**: for each
Role/ClusterRole + binding, it checks 11 rules in isolation — wildcard verbs,
Secrets access, exec/attach, escalation verbs, and so on
(`rbac_service.py:_evaluate_role_risks`). That catches a single dangerous role,
but it cannot see the picture a Zero-Trust review actually cares about:

> *What can this **identity** — this ServiceAccount, user, or group — actually
> do across **all** of its bindings combined, and how far does a compromise of
> it reach?*

Two innocuous-looking Roles bound to the same ServiceAccount can combine into a
cluster-takeover path that neither role trips on its own. A role-centric scan
is structurally blind to it. Zero-Trust analysis is **identity-centric**.

This matters because machine identities are the dominant population and the
least reviewed: Sysdig's 2025 cloud-native usage report found machine
identities outnumber humans roughly **40,000 to 1**, and RBAC is repeatedly
reported as the single most-misconfigured area of Kubernetes security. The
grants exist; nobody aggregates and reviews them per identity.

## Framework anchor — NIST SP 800-207A

We anchor the direction to [NIST SP 800-207A](https://doi.org/10.6028/NIST.SP.800-207A),
the Zero-Trust Architecture model for cloud-native applications (final). Its
core shift is **from network-perimeter to identity-tier policy**: trust is not
granted by location or affiliation but earned per-identity, per-request, under
least privilege, with blast radius minimized. Kubernetes RBAC *is* the
identity-tier authorization layer of a cluster — so a tool that assesses RBAC
posture against these tenets is doing identity-tier Zero-Trust analysis, not
adding a buzzword.

| NIST 800-207A tenet | Kaaval analysis class | Status |
|---|---|---|
| Identity-tier authorization (not network location) | **Effective Access Graph** — per-identity aggregated permissions | this doc, lead build |
| Least privilege, per session | Unused-permission drift (granted vs actually-used) | follow-on, needs audit-log source |
| No implicit trust | Broad-group / default-SA / cross-namespace trust flags (some exist today) | extend existing rules |
| Minimize blast radius | Blast-radius exposure factor on the Contextual Risk Score | follow-on |
| Micro-segmentation | Scope-boundary violations (namespaced identity reaching cluster scope) | follow-on |

Supporting sources: [Kubernetes RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/),
[OWASP Kubernetes Top 10 K03 (broken authN/authZ)](https://owasp.org/www-project-kubernetes-top-ten/).
CISSP mapping: **Domain 5 (Identity & Access Management)** — this is IAM
governance applied to Kubernetes.

## Lead design — the Effective Access Graph

An identity-centric aggregation that **reuses the existing RBAC graph** — no new
data source, no new cluster permissions. It inverts the current loop.

**Today** (`evaluate_rbac_findings`, `rbac_service.py`): iterate *bindings* →
evaluate each referenced role's rules in isolation → name the subject.

**Effective Access Graph:** iterate *subjects* → collect every Role/ClusterRole
bound to that subject (via any RoleBinding or ClusterRoleBinding) → **union all
their rules** into one effective permission set → evaluate that set.

It runs against the same graph from `K8sClient.get_rbac_graph_data()`:

```
roles:                [{name, namespace, rules}]
cluster_roles:        [{name, rules}]
role_bindings:        [{name, namespace, roleRef, subjects}]
cluster_role_bindings:[{name, roleRef, subjects}]
```

### Two kinds of finding it produces

1. **Aggregated single-rule findings.** Run the *existing* predicates
   (`_is_wildcard_open`, `_grants_secrets_access`, `_grants_exec_attach`,
   `_grants_escalation_verbs`, `_grants_token_creation`, …) against the
   **union** of a subject's rules. A subject that is wildcard-open *in
   aggregate* — even though no single bound role is — is now caught.

2. **Combination findings (the real prize).** Dangerous permission *pairs* that
   only exist at the identity level. These are well-documented escalation
   chains ([SchutzWerk](https://www.schutzwerk.com/en/blog/kubernetes-privilege-escalation-01/),
   Kubernetes RBAC Good Practices):

   | Combination (across the identity's bindings) | Why it's a takeover path |
   |---|---|
   | `create`/`update` on `roles`/`clusterroles` **+** `escalate` | self-grant any permission (bypasses the API server's escalation check) |
   | `create` on `rolebindings`/`clusterrolebindings` **+** `bind` | bind self to any role, including `cluster-admin` |
   | `impersonate` on `users`/`groups`/`serviceaccounts` | act as `system:masters` → full cluster access |
   | `create pods` **+** a privileged/secret-bearing ServiceAccount in-namespace | schedule a pod that mounts the SA token → borrow its rights |
   | Secrets `get`/`list` in ns A **+** workload `create` in ns B | cross-namespace exfiltration path |

   Each combination is a new predicate over the aggregated rule set, following
   the exact shape of the existing `_grants_*` helpers.

### Output — unchanged downstream

Each finding emits the **existing finding dict** (`rule_type`, `severity`,
`title`, `binding`/subject, `detail`), so it flows through the shared engine
untouched: `compute_contextual_score()` ranks it, `build_remediation()`
explains and fixes it, and it serializes to JSON / SARIF / PolicyReport / PDF
with no format changes. The subject becomes the finding's primary object (the
`resources[]` entry in PolicyReport, the location in SARIF).

The USP is intact and extended, not diluted: still **contextual** (same score
engine, now with the identity as the unit), **explained** (why this identity is
over-privileged, which bindings combine), **remediable** (which binding to cut,
which role to split). This is the USP applied to a new *analysis class* — not
feature-parity chasing.

### Why this is the foundation

- **No new data source** — reuses the graph the RBAC scanner already builds.
- **Pure function** — fits the architecture; testable with static fixtures, no
  cluster or DB, exactly like `test_rbac_service.py`.
- **Everything else builds on it.** Blast-radius scoring needs the per-identity
  aggregate to measure reach; segmentation analysis needs it to see scope
  crossing; unused-permission drift diffs *this* effective set against audit
  logs. Ship this first and the rest become extensions, not rewrites.

## Non-goals for round 1

- **No audit-log ingestion.** Usage-based least-privilege (granted vs used) is
  the highest-impact follow-on but needs a new data source (Kubernetes audit
  logs); it gets its own design once the Effective Access Graph lands.
- **No live `can-i` / SubjectAccessReview probing.** We analyze the declared
  RBAC graph statically (shift-left friendly, works on manifests). Live
  effective-access probing is a possible later mode, not this round.
- **No RBAC *mutation*.** Kaaval recommends; it never applies. Read-only
  contract unchanged.

## Rollout shape (for the implementing issue)

1. `effective_access.py` (or extend `rbac_service.py`): a pure
   `build_effective_access(graph)` → `{subject_key: aggregated_rules}` mapping,
   then `evaluate_effective_access(graph, context)` returning findings in the
   existing shape. Reuse every existing `_grants_*` predicate; add the
   combination predicates.
2. Fixtures in `hack/dev/rbac-fixtures.yaml`: a subject whose *combination* of
   two benign-looking roles is a takeover path (proves the role-centric scan
   misses it and this catches it).
3. Unit tests mirroring `test_rbac_service.py` (pure, no cluster/DB).
4. Surface via CLI (`--analysis effective-access` or fold into the RBAC scan)
   and the dashboard, both reusing the existing finding UI.
5. Remediation entries in `remediation.py` for each new `rule_type`, with
   verified CIS / RBAC-Good-Practices / OWASP-K03 references (never an invented
   control ID).
