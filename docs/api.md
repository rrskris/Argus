# REST API reference

Base URL: the control plane (default `http://localhost:8000`). Interactive
OpenAPI docs are served at `/docs` (Swagger UI) and `/redoc` by FastAPI.

## Authentication

Login is OAuth2 password flow (form-encoded); everything else takes the
access token as a bearer header. Tokens: short-lived access + refresh.

```bash
# login (admin user is seeded on first startup — see the README)
curl -s -X POST http://localhost:8000/auth/token \
  -d 'username=admin&password=YOUR_PASSWORD'
# → {"access_token": "...", "refresh_token": "...", "token_type": "bearer"}

TOKEN=...   # access_token from above
curl -s http://localhost:8000/auth/me -H "Authorization: Bearer $TOKEN"
# → {"username": "admin", "role": "admin", "tenant_id": "..."}
```

| Method + path | Purpose |
|---|---|
| `POST /auth/token` | Login (form fields `username`, `password`) → token pair |
| `POST /auth/refresh` | Body `{"refresh_token": "..."}` → new token pair |
| `GET /auth/me` | Current user |
| `POST /auth/seed` | (Re-)run admin bootstrap — also runs automatically on startup |
| `GET /` | Unauthenticated health check |
| `GET /license/status` | CE/EE license gate status |

Errors are standard FastAPI shape: `{"detail": "..."}` with 401 (bad/missing
token), 404 (missing resource), 400 (validation), 502 (upstream fetch
failures, e.g. a feed URL that won't load).

## Risk context

The four fields driving the [Contextual Risk Score](contextual-risk-score.md).
Tenant-scoped; shared by CVE and RBAC scans; defaults seeded on first read.

```bash
curl -s http://localhost:8000/cve/context -H "Authorization: Bearer $TOKEN"

curl -s -X PUT http://localhost:8000/cve/context \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"environment": "production", "data_classification": "pii",
       "compliance_scope": ["PCI-DSS"], "exposure": "internet-facing"}'
```

Only provided fields change. Invalid enum values are rejected with 400; the
allowed values are the ones in [contextual-risk-score.md](contextual-risk-score.md).

## CVE scanning

| Method + path | Purpose |
|---|---|
| `POST /cve/scan` | Scan the cluster Argus runs in (or reaches via kubeconfig) against all enabled feeds |
| `GET /cve/scan/latest` | Most recent self-scan result |
| `GET /cve/scan/latest/report.pdf` | Same scan as a PDF |
| `GET /cve/summary` | Feed stats + severity breakdown + latest scan |

Findings in scan results carry: `severity`, `cvss_score` (unchanged,
tool-comparable), `contextual_score`, `score_factors` (every multiplier,
explained), `affected` (component/version matches from *your* cluster),
and `remediation`:

```json
"remediation": {
  "action": "Upgrade kubernetes to 1.29.4 or later.",
  "why_it_matters": "Ranked 30.71 because this is a production environment, ...",
  "compliance_note": "PCI-DSS Req 6.2 — apply security patches for known vulnerabilities.",
  "audit_note": "Document remediation of CVE-XXXX-XXXX as evidence for PCI-DSS audit scope.",
  "benchmark_refs": []
}
```

### Feed management

| Method + path | Purpose |
|---|---|
| `GET /cve/feeds` | List feeds |
| `POST /cve/feeds` | Add a feed — body `{"name", "url", "feed_type": "auto|json_feed|osv|nvd", "description"}`; format auto-detected on fetch |
| `POST /cve/feeds/{id}/refresh` | Fetch/reload one feed |
| `POST /cve/feeds/refresh-all` | Refresh all enabled feeds |
| `PATCH /cve/feeds/{id}/toggle` | Enable/disable |
| `DELETE /cve/feeds/{id}` | Delete feed + entries |
| `GET /cve/entries` | Browse entries (`severity`, `feed_id`, `search`, `limit`, `offset`) |
| `POST /cve/k8s/feed/sync` | Register + refresh the official Kubernetes CVE feed in one call (idempotent) |
| `GET /cve/k8s/feed` | Status of the official feed |

### Multi-cluster (EE path)

| Method + path | Purpose |
|---|---|
| `GET /cve/k8s/clusters` | Registered clusters + latest scan summaries |
| `POST /cve/k8s/clusters/{id}/scan` | Scan one registered cluster |
| `POST /cve/k8s/scan-all` | Scan every active registered cluster |
| `GET /cve/k8s/clusters/{id}/scan/latest` | Latest scan for a cluster |
| `GET /cve/k8s/clusters/{id}/scan/history` | Scan history (`limit`) |

Registered-cluster scans use each cluster's own stored risk context
(`ClusterRegistration.environment` etc.) instead of the tenant default.
Note: there is currently no endpoint to *create* a `ClusterRegistration` —
a known gap from the v1.1.0 cleanup; the self-scan path is the primary one.

## RBAC scanning

| Method + path | Purpose |
|---|---|
| `POST /rbac/scan` | Scan live Roles/ClusterRoles/bindings ([rule catalog](rbac-rules.md)) |
| `GET /rbac/scan/latest` | Most recent RBAC scan |
| `GET /rbac/scan/latest/report.pdf` | Same scan as a PDF |

```bash
curl -s -X POST http://localhost:8000/rbac/scan -H "Authorization: Bearer $TOKEN" \
  | jq '.findings[0] | {rule_type, severity, contextual_score, remediation}'
```

RBAC findings carry the same scoring/remediation fields as CVE findings,
plus `role`, `binding`, `subjects`, and CIS v1.12.0 `benchmark_refs`:

```json
"benchmark_refs": [
  {"benchmark": "CIS Kubernetes Benchmark v1.12.0", "id": "5.1.1",
   "title": "Ensure that the cluster-admin role is only used where required"}
]
```

## Headless / CI

The CLI (`python -m app.cli scan rbac ...`) runs the same rule engine with
no server or DB at all — see [ci-integration.md](ci-integration.md).
