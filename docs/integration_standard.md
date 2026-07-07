# Integration / extension standard

> **Status: design intent, partially implemented.** What exists today: the
> `extensions/` directory of YAML integration packs (e.g.
> `extensions/extensions/integrations/cis-aws-1.5.yaml`) and the
> `TenantFramework` model that links a tenant to an enabled framework. The
> marketplace router and the Go discovery engine described in earlier
> versions of this document were removed in the v1.1.0 cleanup and do not
> exist — this document now records the standard for when that surface is
> rebuilt, without pretending it's live.

## Purpose

Integrations are modular "compliance packs" or external finding sources —
sets of checks (CIS AWS, PCI-DSS mappings) or connectors (Trivy/Grype
reports, Kyverno PolicyReports) that a tenant enables without bloating the
core scanner with logic irrelevant to everyone else.

## The rule every integration must follow

**External findings map into the canonical finding shape and flow through
the existing engines** — `compute_contextual_score()` (`scoring.py`) and
`build_remediation()` (`remediation.py`) — rather than defining their own
severity or advice format. One ranked list, one explanation format, no
parallel alert streams. The worked example of this pattern is the
[Trivy/Grype ingestion design](trivy-grype-integration.md).

## Pack format (`extensions/`)

- **ID**: `vendor-product-version`, kebab-case (e.g. `cis-aws-1.5`)
- **Name**: Title Case (e.g. `CIS AWS Foundations Benchmark`)
- **Version**: semver, incremented on any logic change
- Each pack is one YAML file: metadata (id/name/description/version/tier)
  plus its rule or field-mapping payload.

## Stability rules

1. Each integration is self-contained — no cross-pack imports.
2. Checks return "not applicable" for foreign asset types; never crash the
   scan run.
3. Activation is per-tenant (`TenantFramework`); disabled packs cost nothing
   at scan time.
4. A pack's benchmark citations must name the exact benchmark version
   (e.g. "CIS Kubernetes Benchmark v1.12.0"), the same rule the core
   remediation module follows.
