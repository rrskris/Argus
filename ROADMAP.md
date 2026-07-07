# Roadmap

Where Argus is headed. This is direction, not a dated commitment — and it's
where help is most welcome. Items tagged **[good first issue]** or **[help
wanted]** have (or will have) a matching labeled issue; comment there before
starting so we don't duplicate work.

The through-line never changes: **contextual, explained, remediable
findings** — not raw detection volume. Every item below serves that.

## Shipped

- CVE scanning against live cluster + add-on versions (K8s official feed / OSV / NVD)
- RBAC misconfiguration scanning — 11 rules mapped to CIS Kubernetes Benchmark v1.12.0 §5.1
- Contextual Risk Score engine (shared by every finding type)
- Remediation on every finding — action, why-it-matters, benchmark ref, compliance + audit notes
- Headless CLI with contextual-score CI/CD gating + GitHub Action
- Kyverno admission-time policies mirroring the RBAC rules
- PDF reporting, multi-cluster comparison

## Next — output formats and pipeline reach

- [ ] **SARIF output** from the CLI → GitHub Security tab **[good first issue]**
- [ ] **JUnit XML output** for GitLab/Jenkins test panes **[good first issue]**
- [ ] Prometheus `/metrics` endpoint on the control plane (findings by type/severity, max score, last-scan time) **[help wanted]**
- [ ] `GET /rbac/scan/diff` — compare the two latest scans and alert on *new* findings only **[help wanted]**
- [ ] Scheduled in-cluster scanning (CronJob manifest)

## Next — more finding sources into the same score

- [ ] **Trivy report ingestion** — pure adapter into the finding shape ([design](docs/trivy-grype-integration.md)) **[help wanted]**
- [ ] **Grype report ingestion** — same pattern **[help wanted]**
- [ ] Kyverno PolicyReport ingestion — consume admission results as a finding source

## Next — deeper RBAC + new rule types

- [ ] Additional RBAC rules for CIS §5.1 controls not yet covered (e.g. default-SA token automount) **[good first issue]**
- [ ] Cloud-identity cross-reference — tie a ServiceAccount's IRSA / Workload Identity annotation to its real cloud IAM blast radius **[help wanted]**
- [ ] Auto-detect data classification / exposure from namespace labels (today it's set manually)

## Packaging and adoption

- [ ] Real Helm chart (the `deploy/helm/` stub is currently empty) **[help wanted]**
- [ ] Argo CD / Flux "verify after deploy" recipe shipped as a manifest
- [ ] Publish the GitHub Action to the Marketplace

## Further out

- A parallel Go scanning engine for high-throughput static analysis (`cloud-scanner/` / `agent/` are reserved for this)
- Predictive attack-path mapping (compromised-pod → reachable resources), non-destructive

Want something here that isn't tagged yet? Open a
[rule request or feature issue](https://github.com/rrskris/Argus/issues/new/choose)
and we'll scope it together.
