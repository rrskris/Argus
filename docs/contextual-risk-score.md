# The Contextual Risk Score

Every Kaaval finding — CVE or RBAC — is ranked by one formula, implemented in
`control-plane/app/scoring.py`:

```
score = base × environment × data_classification × compliance_scope × exposure
```

The point is not the number. The point is that the score is **never a black
box**: every finding carries `score_factors` naming each multiplier that was
applied, and the remediation text only cites factors that actually raised the
score. Flat severity sorts — what every other scanner does — make a wildcard
ClusterRole in a throwaway dev cluster look exactly as urgent as the same one
in an internet-facing PCI production cluster. This formula is the fix.

## The weights

**Base** — a CVE uses its CVSS score directly; findings without one (RBAC)
use the severity band:

| Severity | Base |
|---|---|
| CRITICAL | 9.5 |
| HIGH | 7.5 |
| MEDIUM | 5.5 |
| LOW | 2.5 |
| UNKNOWN | 1.0 |

**Multipliers** — from the tenant's risk context:

| Factor | Values → weight |
|---|---|
| `environment` | production ×1.5 · staging ×1.2 · dev ×0.5 |
| `data_classification` | pii ×1.5 · financial ×1.5 · phi ×1.5 · internal ×1.0 · public ×0.8 |
| `compliance_scope` | any framework listed (PCI-DSS/HIPAA/SOC2) ×1.3 · none ×1.0 |
| `exposure` | internet-facing ×1.4 · internal ×1.0 |

## Worked examples

The same CRITICAL RBAC finding (base 9.5):

```
dev cluster, public data, no compliance, internal:
    9.5 × 0.5 × 0.8 × 1.0 × 1.0  =  3.8

production, PII, PCI-DSS, internet-facing:
    9.5 × 1.5 × 1.5 × 1.3 × 1.4  =  38.9
```

Same finding, **10× apart** — and each score explains itself. A HIGH CVE
(CVSS 7.5) in that production context scores 30.71, still ranking above a
CRITICAL in dev. That's intended: contextual ranking is the whole feature.

Each finding's `score_factors` looks like:

```json
{
  "base_severity":       {"value": "CRITICAL", "raw_score": null, "weight": 9.5},
  "environment":         {"value": "production", "weight": 1.5},
  "data_classification": {"value": "pii", "weight": 1.5},
  "compliance_scope":    {"value": ["PCI-DSS"], "weight": 1.3},
  "exposure":            {"value": "internet-facing", "weight": 1.4}
}
```

The dashboard renders the factors with weight > 1.0 as "why it's ranked
here"; the PDF and the remediation object do the same in prose.

## Setting the risk context

Three ways, same four fields:

1. **Dashboard** — Settings → Risk Context.
2. **API** — `PUT /cve/context` (see [api.md](api.md)); the context is
   tenant-scoped and shared by CVE and RBAC scans. Defaults are seeded on
   first access: production / internal / internal, no compliance scope.
3. **CLI / CI** — a committed `kaaval.yaml` per environment overlay
   ("risk context as code", see [ci-integration.md](ci-integration.md)).

## Design choices, stated plainly

- **Multiplicative, not additive** — context should scale urgency, not nudge
  it. A dev-environment weight of 0.5 halving everything is the honest
  statement that dev findings are usually not incidents.
- **Small, legible weight tables** — auditable at a glance in `scoring.py`.
  Custom per-org weights are on the roadmap; the current formula is
  fixed so that a score of 38.9 means the same thing in every report.
- **Score explains ranking; severity stays untouched** — `severity` and
  `cvss_score` fields are unchanged on every finding, so anything built on
  severity keeps working, and the CVSS number stays comparable across tools.
- **Context is declared, not inferred** — Kaaval does not guess your data
  classification. Auto-detection (e.g. from namespace labels) is on the
  roadmap; guessing wrong silently would be worse than asking.
