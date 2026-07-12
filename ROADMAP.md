# Roadmap

Where Kaaval is headed. Every "next" item links to a labeled issue — comment
there before starting so we don't duplicate work. Items are grouped into
GitHub [milestones](https://github.com/kaaval/kaaval/milestones); dates are
direction, not commitments.

The through-line never changes: **contextual, explained, remediable
findings** — not raw detection volume. Every item below serves that.

## Shipped

- CVE scanning against live cluster + add-on versions (K8s official feed / OSV / NVD)
- RBAC misconfiguration scanning — 11 rules mapped to CIS Kubernetes Benchmark v1.12.0 §5.1
- Contextual Risk Score engine (shared by every finding type)
- Remediation on every finding — action, why-it-matters, benchmark ref, compliance + audit notes
- Headless CLI with contextual-score CI/CD gating + GitHub Action
- **PolicyReport output** (`wgpolicyk8s.io/v1alpha2`) — findings consumable by policy-reporter, side by side with Kyverno/Falco/Trivy-operator ([docs](docs/ci-integration.md#policyreport-output-kubernetes-policy-ecosystem))
- Kyverno admission-time policies mirroring the RBAC rules — two contributed upstream ([ledger](docs/upstream-contributions.md))
- PDF reporting, multi-cluster comparison
- Signed releases: cosign keyless signatures, SPDX SBOMs, build provenance

## Milestone v1.2 — pipeline reach

- [ ] SARIF output → GitHub Security tab — [#1](https://github.com/kaaval/kaaval/issues/1), in review ([#10](https://github.com/kaaval/kaaval/pull/10))
- [ ] JUnit XML output for GitLab/Jenkins test panes — [#2](https://github.com/kaaval/kaaval/issues/2) **[good first issue]**
- [ ] Feed GitHub alert ranking (`security-severity`) from the Contextual Risk Score — [#32](https://github.com/kaaval/kaaval/issues/32)
- [ ] Friendly CLI error for unreadable manifest paths — [#30](https://github.com/kaaval/kaaval/issues/30) **[good first issue]**
- [ ] CronJob manifest for scheduled in-cluster scans — [#33](https://github.com/kaaval/kaaval/issues/33) **[good first issue]**
- [ ] Argo CD / Flux "verify after deploy" recipe using PolicyReport output — [#38](https://github.com/kaaval/kaaval/issues/38) **[good first issue]**
- [ ] Real Helm chart (`deploy/helm/` is an empty stub) — [#8](https://github.com/kaaval/kaaval/issues/8) **[help wanted]**
- [ ] Publish the GitHub Action to the Marketplace — [#34](https://github.com/kaaval/kaaval/issues/34)

## Milestone v1.3 — more sources, same score

The moat is the scoring/explanation layer; every new source feeds it through
a pure adapter ([pattern](docs/trivy-grype-integration.md)).

- [ ] Trivy report ingestion — [#5](https://github.com/kaaval/kaaval/issues/5) **[help wanted]**
- [ ] Grype report ingestion — [#6](https://github.com/kaaval/kaaval/issues/6) **[help wanted]**
- [ ] Kyverno PolicyReport **ingestion** — consume admission results as a finding source — [#35](https://github.com/kaaval/kaaval/issues/35) **[help wanted]**
- [ ] Prometheus `/metrics` endpoint — [#3](https://github.com/kaaval/kaaval/issues/3) **[help wanted]**
- [ ] `GET /rbac/scan/diff` — alert on *new* findings only — [#4](https://github.com/kaaval/kaaval/issues/4) **[help wanted]**
- [ ] More CIS §5.1 rules (e.g. default-SA token automount) — [#7](https://github.com/kaaval/kaaval/issues/7) **[good first issue]**
- [ ] Auto-detect data classification / exposure from namespace labels — [#36](https://github.com/kaaval/kaaval/issues/36)

## Milestone v1.4 — Zero-Trust posture

Kaaval today does role-centric dangerous-permission detection; Zero-Trust is
identity-centric — what each identity can *actually* do across all its bindings,
and how far a compromise reaches. Anchored to
[NIST SP 800-207A](https://doi.org/10.6028/NIST.SP.800-207A). Full design:
[docs/design/zero-trust-rbac.md](docs/design/zero-trust-rbac.md).

- [ ] **Effective Access Graph** — per-identity aggregated permissions + combination escalation paths (the lead build) — [#47](https://github.com/kaaval/kaaval/issues/47) **[help wanted]**
- [ ] Blast-radius exposure factor on the Contextual Risk Score — [#48](https://github.com/kaaval/kaaval/issues/48) **[help wanted]**
- [ ] Segmentation-violation rule (namespaced identity reaching cluster scope) — [#49](https://github.com/kaaval/kaaval/issues/49) **[good first issue]**
- [ ] Usage-based least-privilege via audit-log ingestion (design first) — [#50](https://github.com/kaaval/kaaval/issues/50) **[help wanted]**

## Milestone v2.0 — the differentiators

- [ ] Cloud-identity cross-reference — tie a ServiceAccount's IRSA / Workload Identity annotation to its real cloud IAM blast radius — [#37](https://github.com/kaaval/kaaval/issues/37) **[help wanted]**
- [ ] Parallel Go scanning engine for high-throughput static analysis (`cloud-scanner/` / `agent/` are reserved for this)
- [ ] Predictive attack-path mapping (compromised-pod → reachable resources), non-destructive

## How this ladders to CNCF

Kaaval is built toward a **CNCF Sandbox application**, deliberately:

1. **Standards in both directions** — we emit the ecosystem's formats
   (PolicyReport, SARIF) and ingest them (Trivy, Grype, Kyverno PolicyReports)
   rather than inventing our own. v1.2/v1.3 above are that story. The
   Zero-Trust posture work (v1.4) is anchored to
   [NIST SP 800-207A](https://doi.org/10.6028/NIST.SP.800-207A) and the
   Kubernetes RBAC Good Practices — recognized frameworks, not invented ones.
2. **Upstream first** — where a gap belongs in someone else's project, we fix
   it there ([contributions ledger](docs/upstream-contributions.md)).
3. **Governance and supply chain** already follow CNCF norms: vendor-neutral
   [GOVERNANCE](GOVERNANCE.md), DCO, OpenSSF Scorecard, signed releases with
   SBOM + provenance, no feature gates of any kind.
4. **Evidence over claims** — [ADOPTERS.md](ADOPTERS.md) entries and sustained
   multi-contributor activity are what a Sandbox application is judged on.
   Using Kaaval? [Add yourself](ADOPTERS.md); it directly helps.

Want something here that isn't tagged yet? Open a
[rule request or feature issue](https://github.com/kaaval/kaaval/issues/new/choose)
and we'll scope it together.
