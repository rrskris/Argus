# Kaaval

[![CI](https://github.com/kaaval/kaaval/actions/workflows/ci.yml/badge.svg)](https://github.com/kaaval/kaaval/actions/workflows/ci.yml)
[![Published images](https://github.com/kaaval/kaaval/actions/workflows/smoke-published.yml/badge.svg)](https://github.com/kaaval/kaaval/actions/workflows/smoke-published.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/kaaval/kaaval/badge)](https://scorecard.dev/viewer/?uri=github.com/kaaval/kaaval)
[![Release](https://img.shields.io/github/v/release/kaaval/kaaval?include_prereleases)](https://github.com/kaaval/kaaval/releases)
[![License](https://img.shields.io/github/license/kaaval/kaaval)](LICENSE)
[![Good first issues](https://img.shields.io/github/issues/kaaval/kaaval/good%20first%20issue?label=good%20first%20issues&color=7057ff)](https://github.com/kaaval/kaaval/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
[![Invigil doctrine grade](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/invigil/invigil/main/badges/kaaval.json)](https://github.com/invigil/invigil)

**A self-hosted Kubernetes security scanner that tells you what a finding actually means for *your* cluster — not just a list of IDs to look up yourself.**

> *Kaaval (కావల్) means "guard duty" — the act of keeping watch. Formerly known as Argus; renamed to avoid colliding with the long-running [openargus](https://openargus.org) network audit project.*

![Kaaval scanning deliberately vulnerable RBAC and ranking findings by contextual risk](docs/assets/kaaval-scan.gif)

Most scanners stop at detection: here's 800 CVEs, here's 50 risky RBAC bindings, good luck prioritizing them. Kaaval is built around a different principle — a finding is only useful once it's tied to *your* environment and comes with a concrete next step. Every finding, whether it's a CVE or an RBAC misconfiguration, is run through the same **Contextual Risk Score** engine and ranked by what actually matters to you, not a flat severity sort.

## What it does today

- **CVE scanning** — connects to your live cluster (in-cluster or via kubeconfig), fingerprints the control plane version and running add-ons (`ingress-nginx`, `coredns`, `metrics-server`, CSI drivers, etc.), and cross-references what's actually running against the official Kubernetes CVE feed and NVD. No guessing which CVEs apply to you — only the ones that match your real component versions show up.
- **RBAC misconfiguration scanning** — walks every Role, ClusterRole, and binding in the cluster against 11 rules covering the CIS Kubernetes Benchmark v1.12.0 section 5.1 controls that are inspectable from RBAC state: wildcard permissions, Secrets access, exec/attach grants, escalate/bind/impersonate verbs, `nodes/proxy`, CSR approval, webhook config writes, ServiceAccount token creation, workload/PV creation, and cluster-admin bound to broad identities (`default` SA, `system:authenticated`, `system:masters`). Built-in system roles are filtered out so you see real problems, not platform internals. Full catalog: [docs/rbac-rules.md](docs/rbac-rules.md).
- **Contextual Risk Score** — the same CVE or RBAC finding ranks differently depending on your answers to four questions: is this production or dev? What data lives here (PII, financial, PHI)? Which compliance frameworks apply (PCI-DSS, HIPAA, SOC2)? Is it internet-facing? The score is never a black box — every finding shows exactly which factors pushed it up or down. Formula and weights: [docs/contextual-risk-score.md](docs/contextual-risk-score.md).
- **Remediation on every finding** — not just detection: each finding carries what to do (with the `kubectl` command), why it matters in *your* context, the CIS v1.12.0 control it maps to, a compliance note (PCI-DSS/HIPAA/SOC2), and an audit-trail note — in the API, the dashboard, and the PDF.
- **CI/CD gating** — a headless CLI scans RBAC manifests at PR time (shift-left) or a live cluster post-deploy, and fails the pipeline on the *contextual* score, not a flat severity: the same finding that blocks a production/PCI pipeline can pass in dev. Ships with a GitHub Action and GitLab/Jenkins/Argo CD recipes: [docs/ci-integration.md](docs/ci-integration.md).
- **PolicyReport output** — findings emit as Kubernetes-standard [PolicyReport CRDs](https://github.com/kubernetes-sigs/wg-policy-prototypes/tree/master/policy-report) (`--output policyreport`), so they land in [policy-reporter](https://kyverno.github.io/policy-reporter/) side by side with Kyverno and Falco results — contextual score and remediation included.
- **PDF reporting** — export any scan (CVE or RBAC) as a shareable report.
- **Multi-cluster comparison** — register multiple clusters and scan/compare across them.
- **Kyverno policies** — admission-time counterparts of the RBAC rules in [`policies/kyverno/`](policies/kyverno/README.md), with an honest map of what the upstream policy library already covers and two policies being contributed upstream.

## Screenshots

Every RBAC misconfiguration is ranked by the Contextual Risk Score and expands into a full remediation block — what to do, why it matters *in your context*, the CIS Kubernetes Benchmark v1.12.0 control it maps to, the compliance note, and an audit-trail line:

![RBAC finding with contextual score and full remediation](docs/assets/screenshots/rbac-remediation.png)

The ranked findings list — the same score sorts a CRITICAL `system:masters` binding above expected-but-noisy HIGH grants:

![Ranked RBAC findings](docs/assets/screenshots/rbac-findings.png)

The four risk-context answers that drive the score, set once per cluster:

![Risk context settings](docs/assets/screenshots/risk-context.png)

Dashboard overview:

![Dashboard](docs/assets/screenshots/dashboard.png)

## Why it's different

Detection tools (Trivy, Prowler, kube-bench) tell you *what's wrong*. SaaS platforms (Wiz, Orca) add business context but keep the scoring model opaque and the price tag five figures. Kaaval does the contextual scoring in the open, self-hosted, with the formula visible in the code — you can see exactly why a finding ranks where it does.

## Architecture

```
control-plane/   FastAPI backend — auth, CVE + RBAC scanning, contextual scoring, PDF reporting
dashboard/       Next.js frontend — scan results, feed management, risk context settings, PDF export
deploy/          docker-compose stack (Postgres + control-plane + dashboard)
```

**Control plane** ingests CVE feeds (`cve_service.py`), connects to the cluster (`k8s_client.py`), detects running add-ons by image (`addon_detection.py`), evaluates RBAC risk rules (`rbac_service.py`), and scores every finding through one shared engine (`scoring.py`) so CVE and RBAC findings are ranked the same way. Results are exposed over a REST API and exportable as PDF (`report_service.py`).

Key endpoints (full reference: [docs/api.md](docs/api.md)):
- `POST /cve/scan`, `GET /cve/scan/latest`, `GET /cve/scan/latest/report.pdf` — scan the connected cluster, fetch or export the last result
- `GET /cve/summary` — severity breakdown across the current feed
- `POST /cve/k8s/clusters/{id}/scan`, `GET /cve/k8s/clusters` — multi-cluster scanning and comparison
- `GET|POST /cve/feeds` — manage which CVE feeds are active
- `GET|PUT /cve/context` — read/update your tenant's risk context (environment, data classification, compliance scope, exposure) that drives the Contextual Risk Score
- `POST /rbac/scan`, `GET /rbac/scan/latest`, `GET /rbac/scan/latest/report.pdf` — scan the cluster's Roles/ClusterRoles/bindings for misconfigurations, fetch or export the result

Kaaval is fully open source under Apache-2.0 — no open-core split, no feature gates, no license tokens. Everything the project ships runs self-hosted, and it will stay that way: the project is being built toward CNCF vendor-neutrality standards.

## Quickstart

### 1. See it work in under two minutes (throwaway cluster)

You need Docker, [`kind`](https://kind.sigs.k8s.io/), `kubectl`, and Python 3.14:

```bash
git clone https://github.com/kaaval/kaaval && cd kaaval
make setup-dev        # kind cluster preloaded with deliberately-vulnerable RBAC
make scan             # findings ranked by contextual risk, remediation included
make teardown-dev     # clean up
```

No cluster handy? `make scan-manifests` scans the fixture YAML directly — no
Kubernetes at all.

### 2. Scan your own manifests in CI (no server, no database)

Straight from the published image, no build:

```bash
docker run --rm -v "$PWD/k8s:/scan" ghcr.io/kaaval/kaaval \
    scan rbac --manifests /scan --fail-on-score 20
```

> On SELinux-enforcing hosts (Fedora, RHEL), add `:z` to the volume flag
> (`-v "$PWD/k8s:/scan:z"`) or the container can't read the mount.

There's also a [GitHub Action](docs/ci-integration.md) plus GitLab/Jenkins/Argo CD
recipes, and gating on the *contextual* score means the same finding can block a
production/PCI pipeline yet pass in dev.

### 3. Full stack with the dashboard

```bash
cp deploy/.env.example deploy/.env
# fill in POSTGRES_PASSWORD, KAAVAL_SECRET_KEY, KAAVAL_REFRESH_SECRET_KEY
# (generate secrets with: openssl rand -hex 32)

docker compose -f deploy/docker-compose.yml up -d
```

The admin user is seeded automatically on first start. If `KAAVAL_ADMIN_PASSWORD` is left blank in `.env`, a password is generated and printed once to the control-plane container logs:

```bash
docker compose -f deploy/docker-compose.yml logs control-plane | grep "Admin created"
```

Dashboard: http://localhost:3000. API: http://localhost:8000.

## Status

| Component | State |
|---|---|
| `control-plane/` — CVE + RBAC scanning, contextual scoring, remediation, PDF, CLI | ✅ shipped, tested, in the published image |
| `dashboard/` — Next.js UI | ✅ shipped |
| `policies/kyverno/` — admission-time counterparts | ✅ shipped |
| `deploy/helm/` | 🚧 planned ([#8](https://github.com/kaaval/kaaval/issues/8)) |
| `agent/`, `cloud-scanner/` — Go engine | 📐 reserved skeletons, not functional (see their READMEs) |
| `plugins/` — integration descriptors | 📐 reserved, no runtime |

Where this is going: [ROADMAP.md](ROADMAP.md). **Using Kaaval?** Add yourself to
[ADOPTERS.md](ADOPTERS.md) — adopter entries directly support the project's CNCF path.

## Development

```bash
# control-plane
cd control-plane
pip install -r requirements.txt
KAAVAL_ADMIN_PASSWORD=test-admin-password pytest tests/

# dashboard
cd dashboard
npm ci
npm run dev
```

## Documentation

Detailed docs live in [docs/](docs/README.md): architecture, the scoring
formula, the full RBAC rule catalog with CIS v1.12.0 mappings, the REST API
reference, and CI/CD integration recipes.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
