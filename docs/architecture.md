# Architecture

```
┌─────────────┐     ┌──────────────────────────────┐     ┌────────────┐
│  dashboard/ │────▶│        control-plane/        │────▶│  Postgres  │
│  Next.js    │ JWT │  FastAPI                     │     │ (scans,    │
│  :3000      │     │  :8000                       │     │  feeds,    │
└─────────────┘     │                              │     │  users)    │
                    │  feeds ─▶ matcher ─┐         │     └────────────┘
┌─────────────┐     │                    ▼         │
│ CVE feeds   │────▶│   pure core: scoring.py      │     ┌────────────┐
│ k8s.io/OSV/ │     │   remediation.py             │◀───▶│ Kubernetes │
│ NVD         │     │   rbac_service rules         │ RO  │ API server │
└─────────────┘     └──────────────┬───────────────┘     └────────────┘
                                   │ same code, no server
                    ┌──────────────▼───────────────┐
                    │  app/cli.py  (CI/CD gating)  │
                    └──────────────────────────────┘
```

Three deployable pieces (`deploy/docker-compose.yml`): Postgres, the
control plane, the dashboard. `agent/` and `cloud-scanner/` are skeletons
reserved for the planned Go engine — no source yet.

## The pure-function core

The deliberate architectural decision: detection, scoring, and explanation
are **pure functions** with no I/O —

- `scoring.py` — `compute_contextual_score(raw_score, severity, context)`
  → `(score, factors)`. One engine for every finding type.
- `remediation.py` — `build_remediation(finding)` → action / why-it-matters /
  CIS v1.12.0 benchmark refs / compliance note / audit note. Handles both
  finding shapes (CVE and RBAC).
- `rbac_service.evaluate_rbac_findings(graph, context)` — the RBAC rule
  engine ([rule catalog](rbac-rules.md)). Takes a plain dict graph, returns
  scored findings.

Everything else is a front door onto that core:

| Front door | Feeds it | Adds |
|---|---|---|
| FastAPI routers | live cluster via `k8s_client.py` | persistence, auth, multi-tenant context |
| PDF export (`report_service.py`) | persisted scans | shareable report |
| CLI (`app/cli.py`) | manifests dir **or** kubeconfig | exit-code gating for pipelines — no DB, no auth, no server |
| (planned) Trivy/Grype ingest | their JSON reports | same scoring on image CVEs — see [trivy-grype-integration.md](trivy-grype-integration.md) |

This is why the CI story is cheap: the CLI is ~300 lines of argument parsing
and YAML→graph mapping around code that already existed and was already
tested.

## Control-plane modules

| Module | Responsibility |
|---|---|
| `main.py` | app wiring, auth endpoints, admin bootstrap (`seed_admin_user`) |
| `auth.py` | JWT access+refresh tokens, password hashing |
| `cve_service.py` | feed fetch/parse (K8s JSON Feed / OSV / NVD auto-detected), cluster inventory, CVE↔version matching |
| `addon_detection.py` | add-on fingerprinting from container images (ingress-nginx, coredns, CSI…) |
| `k8s_client.py` | in-cluster or kubeconfig client; `get_rbac_graph_data()` returns the graph shape the rule engine consumes |
| `rbac_service.py` | RBAC rules + suppression logic + scan persistence |
| `scoring.py` | Contextual Risk Score engine + valid context enums |
| `remediation.py` | per-finding remediation objects + CIS v1.12.0 mapping |
| `report_service.py` | CVE + RBAC PDF reports |
| `cli.py` | headless scan + gating for CI/CD |
| `models.py` | SQLAlchemy models (below) |
| `audit.py` | audit log entries |

## Data model (the parts that matter)

- `Tenant`, `User` — single-tenant in practice today; every scoped table
  carries `tenant_id`.
- `ScanContext` — the four risk-context fields, one row per tenant
  (self-scan path). `ClusterRegistration` carries the same four fields for
  the multi-cluster path.
- `CVEFeed` / `CVEEntry` — feed registry and parsed entries.
- `CVEScanResult` / `K8sCVEScanResult` / `RBACScanResult` — persisted scans;
  findings are stored as JSON **including** their `contextual_score`,
  `score_factors`, and `remediation`, so a report re-rendered later shows
  what the scan said at the time, not what today's context would say.

## Cluster permissions

The scanner needs read-only access:

| API group | Resources | Verbs | For |
|---|---|---|---|
| `rbac.authorization.k8s.io` | roles, clusterroles, rolebindings, clusterrolebindings | get, list | RBAC scan |
| `""` (core) | nodes | get, list | version inventory |
| `apps` | deployments, daemonsets | get, list | add-on detection |

No write verbs anywhere — Kaaval recommends fixes, it does not apply them.

## Licensing

Everything documented here — scanning, scoring, PDF export, CI gating,
multi-cluster comparison — is Apache-2.0 open source and self-hosted with
no license gates of any kind. The project targets CNCF vendor-neutrality
standards; there is no enterprise tier and no reserved feature set.
