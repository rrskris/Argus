# Argus

**A self-hosted Kubernetes security scanner that tells you what a finding actually means for *your* cluster — not just a list of IDs to look up yourself.**

Most scanners stop at detection: here's 800 CVEs, here's 50 risky RBAC bindings, good luck prioritizing them. Argus is built around a different principle — a finding is only useful once it's tied to *your* environment and comes with a concrete next step. Every finding, whether it's a CVE or an RBAC misconfiguration, is run through the same **Contextual Risk Score** engine and ranked by what actually matters to you, not a flat severity sort.

## What it does today

- **CVE scanning** — connects to your live cluster (in-cluster or via kubeconfig), fingerprints the control plane version and running add-ons (`ingress-nginx`, `coredns`, `metrics-server`, CSI drivers, etc.), and cross-references what's actually running against the official Kubernetes CVE feed and NVD. No guessing which CVEs apply to you — only the ones that match your real component versions show up.
- **RBAC misconfiguration scanning** — walks every Role, ClusterRole, and binding in the cluster looking for wildcard permissions, broad Secrets access, pod exec/attach grants, and cluster-admin-equivalent access handed to broad identities (default service accounts, `system:authenticated`). Filters out the expected noise from Kubernetes' own built-in system roles so you see real problems, not platform internals.
- **Contextual Risk Score** — the same CVE or RBAC finding ranks differently depending on your answers to four questions: is this production or dev? What data lives here (PII, financial, PHI)? Which compliance frameworks apply (PCI-DSS, HIPAA, SOC2)? Is it internet-facing? The score is never a black box — every finding shows exactly which factors pushed it up or down.
- **PDF reporting** — export any scan as a shareable report.
- **Multi-cluster comparison** — register multiple clusters and scan/compare across them.

## Why it's different

Detection tools (Trivy, Prowler, kube-bench) tell you *what's wrong*. SaaS platforms (Wiz, Orca) add business context but keep the scoring model opaque and the price tag five figures. Argus does the contextual scoring in the open, self-hosted, with the formula visible in the code — you can see exactly why a finding ranks where it does.

## Architecture

```
control-plane/   FastAPI backend — auth, CVE + RBAC scanning, contextual scoring, PDF reporting
dashboard/       Next.js frontend — scan results, feed management, risk context settings, PDF export
deploy/          docker-compose stack (Postgres + control-plane + dashboard)
```

**Control plane** ingests CVE feeds (`cve_service.py`), connects to the cluster (`k8s_client.py`), detects running add-ons by image (`addon_detection.py`), evaluates RBAC risk rules (`rbac_service.py`), and scores every finding through one shared engine (`scoring.py`) so CVE and RBAC findings are ranked the same way. Results are exposed over a REST API and exportable as PDF (`report_service.py`).

Key endpoints:
- `POST /cve/scan`, `GET /cve/scan/latest`, `GET /cve/scan/latest/report.pdf` — scan the connected cluster, fetch or export the last result
- `GET /cve/summary` — severity breakdown across the current feed
- `POST /cve/k8s/clusters/{id}/scan`, `GET /cve/k8s/clusters` — multi-cluster scanning and comparison
- `GET|POST /cve/feeds` — manage which CVE feeds are active
- `GET|PUT /cve/context` — read/update your tenant's risk context (environment, data classification, compliance scope, exposure) that drives the Contextual Risk Score
- `POST /rbac/scan`, `GET /rbac/scan/latest` — scan the cluster's Roles/ClusterRoles/bindings for misconfigurations

Argus is structured open-core (see `control-plane/app/license.py`): everything above is Community Edition and runs fully self-hosted with no license required. Advanced compliance mapping, SSO, multi-cluster fleet management, and other Enterprise features are gated behind an optional license token — none of that is required to use the scanner.

## Quickstart

```bash
cp deploy/.env.example deploy/.env
# fill in POSTGRES_PASSWORD, ARGUS_SECRET_KEY, ARGUS_REFRESH_SECRET_KEY
# (generate secrets with: openssl rand -hex 32)

docker compose -f deploy/docker-compose.yml up -d
```

The admin user is seeded automatically on first start. If `ARGUS_ADMIN_PASSWORD` is left blank in `.env`, a password is generated and printed once to the control-plane container logs:

```bash
docker compose -f deploy/docker-compose.yml logs control-plane | grep "Admin created"
```

Dashboard: http://localhost:3000. API: http://localhost:8000.

## Development

```bash
# control-plane
cd control-plane
pip install -r requirements.txt
ARGUS_ADMIN_PASSWORD=test-admin-password pytest tests/

# dashboard
cd dashboard
npm ci
npm run dev
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
