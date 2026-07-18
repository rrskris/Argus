# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Project renamed: Argus → Kaaval** (కావల్, "guard duty / keeping watch") to avoid
  colliding with the long-running openargus.org network audit project. Repo is now
  `github.com/kaaval/kaaval`, images are `ghcr.io/kaaval/kaaval` and
  `ghcr.io/kaaval/kaaval-dashboard`, env vars are `KAAVAL_*` (were `ARGUS_*`), the
  GitHub Action lives at `.github/actions/kaaval-scan`, and the CLI context file is
  `kaaval.yaml`. Old GitHub URLs redirect; old `argus-k8s` images stay up but frozen.
- Container images now publish to GHCR on every push to `main` (`:edge`, `:sha-*`)
  and on `v*` tags.
- Container entrypoint dispatches: `docker run … scan rbac …` runs the headless CLI,
  no arguments (or `serve`) runs the API server.

### Added
- **`--version` flag and JUnit XML output** (`--output junit`): version is
  single-sourced from `app.__version__` (fixing the stale hardcoded API version),
  and findings emit as JUnit testcases for GitLab/Jenkins test panes — a clean
  scan emits one passing case instead of an empty suite. Contributed by
  [@donkk11](https://github.com/donkk11) (#81).
- **SARIF `security-severity`**: SARIF rules carry a `security-severity` scaled from
  the per-rule maximum Contextual Risk Score (capped by `MAX_CONTEXTUAL_SCORE`,
  derived from the scoring weight maxima), so GitHub's Security-tab ordering mirrors
  Kaaval's contextual ranking. Contributed by
  [@Diyaaa-12](https://github.com/Diyaaa-12) (#56).
- **Scheduled in-cluster scans**: `deploy/cronjob.yaml` runs the headless CLI on a
  schedule and applies findings as PolicyReport/ClusterPolicyReport documents —
  init-container scans, pinned-kubectl main container applies, minimal split
  ClusterRoles, hardened pod security context. Contributed by
  [@Maqbool61](https://github.com/Maqbool61) (#59).
- **PolicyReport output** (`--output policyreport`): findings emit as Kubernetes
  Policy WG `wgpolicyk8s.io/v1alpha2` PolicyReport/ClusterPolicyReport documents —
  one report per namespace plus a cluster report — with contextual score,
  remediation, and CIS refs in `properties`. Validated against the wg-policy CRDs
  in a live cluster and consumed by policy-reporter under `source: Kaaval`.
- Roadmap v2: every item tied to a labeled issue and a GitHub milestone
  (v1.2 / v1.3 / v2.0), plus an explicit "how this ladders to CNCF" section.
- RBAC misconfiguration scanning: 11 rules mapped to CIS Kubernetes Benchmark
  v1.12.0 §5.1, with per-finding remediation (kubectl command, why-it-matters,
  benchmark refs, compliance + audit notes).
- Contextual Risk Score engine shared by CVE and RBAC findings — environment, data
  classification, compliance scope, and exposure drive the ranking, with visible
  score factors.
- Headless CLI (`python -m app.cli scan rbac`) for CI/CD: manifests (shift-left) or
  live cluster, `--fail-on-score` / `--fail-on-severity` gating, JSON/table output,
  plus a composite GitHub Action.
- RBAC scan PDF export (`GET /rbac/scan/latest/report.pdf`).
- Kyverno admission-time counterparts of the RBAC rules (`policies/kyverno/`), with
  two policies staged for upstream contribution to `kyverno/policies`.
- Documentation set: architecture, API reference, RBAC rule catalog, contextual-risk
  score formula, CI integration, Trivy/Grype ingestion design.
- Project governance: GOVERNANCE.md, MAINTAINERS.md, ADOPTERS.md, full Contributor
  Covenant v2.1, DCO sign-off requirement, CHANGELOG.

### Fixed
- CLI exits 2 with an actionable error when the `--manifests` path is missing or
  unreadable, instead of silently reporting a clean scan — `Path.rglob()` swallows
  `EACCES` during traversal, so unreadable directories previously produced a false
  exit 0. Regression tests exercise real chmod-000 conditions. Contributed by
  [@donkk11](https://github.com/donkk11) (#45).

### Removed
- The vestigial CE/EE license gate (`license.py`) and every "Enterprise tier"
  reference. Kaaval is fully open source with no feature gates, aligned with CNCF
  vendor-neutrality standards.

## [1.1.0] - 2026-07-06

First public release, at the time under the name **Argus**.

### Added
- Kubernetes CVE scanning: fingerprints the live cluster (control-plane version +
  running add-ons: ingress-nginx, coredns, metrics-server, CSI drivers) and matches
  against the Kubernetes official CVE feed, OSV, and NVD.
- CVE scan PDF reporting.
- Next.js dashboard (scan results, feed management, settings, login).
- Multi-cluster registration and comparison.
- CI: control-plane pytest against a real Postgres service container; dashboard
  lint + build.
- Apache-2.0 license.

### Removed
- All dead pre-launch "Pro-NDS" enterprise-console code (12 backend routers,
  13 dashboard pages) that called APIs which no longer existed.

[Unreleased]: https://github.com/kaaval/kaaval/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/kaaval/kaaval/releases/tag/v1.1.0
