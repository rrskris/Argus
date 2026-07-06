# Argus

Kubernetes CVE visibility that tells you what a finding actually means for *your* cluster — not just a feed of CVE IDs.

Argus scans your live cluster (control plane version, running add-ons like `ingress-nginx`, `coredns`, `metrics-server`, CSI drivers) against the official Kubernetes CVE feed and NVD, matches what's actually running against what's actually affected, and gives you a severity-ranked, remediation-first report instead of a raw vulnerability dump.

## Why

Most CVE tooling stops at detection: here's a list of 800 CVEs, good luck. Argus is built around a different principle — a finding is only useful if it comes with *what it means here* and *what to do about it*. Every scan result ties a CVE to the specific component version running in your cluster and a concrete upgrade path, not just a CVSS score.

## Architecture

```
control-plane/   FastAPI backend — auth, CVE feed ingestion, cluster scanning, PDF reporting
dashboard/       Next.js frontend — scan results, feed management, PDF export
deploy/          docker-compose stack (Postgres + control-plane + dashboard)
```

**Control plane** ingests CVE feeds (Kubernetes official feed + NVD, filtered for k8s/containerd), connects to a cluster via the in-cluster or kubeconfig client (`k8s_client.py`), detects running add-ons by image (`addon_detection.py`), and cross-references versions against feed data (`cve_service.py`). Results are exposed over a small REST API and can be exported as a PDF (`report_service.py`).

Key endpoints (see `control-plane/app/routers/cve.py`):
- `POST /cve/scan`, `GET /cve/scan/latest` — scan the connected cluster / fetch last result
- `GET /cve/scan/latest/report.pdf` — download the scan as a PDF report
- `GET /cve/summary` — severity breakdown across the current feed
- `POST /cve/k8s/clusters/{id}/scan`, `GET /cve/k8s/clusters` — multi-cluster scanning and comparison
- `GET|POST /cve/feeds` — manage which CVE feeds are active

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
