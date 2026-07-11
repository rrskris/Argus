# Kaaval documentation

Start with the [project README](../README.md) for what Kaaval is and the
quickstart. This directory is the detail:

| Doc | What it covers |
|---|---|
| [architecture.md](architecture.md) | Components, data flow, the pure-function core, DB models, cluster permissions, licensing |
| [contextual-risk-score.md](contextual-risk-score.md) | The scoring formula, exact weights, worked examples, how to set the risk context, design rationale |
| [rbac-rules.md](rbac-rules.md) | Every RBAC rule: triggers, severities, CIS v1.12.0 mappings, suppression logic, expected-finding notes |
| [api.md](api.md) | REST reference: auth flow, every endpoint, request/response examples |
| [ci-integration.md](ci-integration.md) | The headless CLI, `kaaval.yaml` risk-context-as-code, exit-code gating, GitHub Actions / GitLab / Jenkins / Argo CD recipes |
| [trivy-grype-integration.md](trivy-grype-integration.md) | Design (not yet built): ingesting Trivy/Grype reports into the same scoring pipeline |
| [integration_standard.md](integration_standard.md) | Extension-pack standard (design intent, partially implemented) |
| [sig-security-intro.md](sig-security-intro.md) | Draft introduction for the Kubernetes SIG Security Tooling community |

Related, outside this directory:

- [`policies/kyverno/`](../policies/kyverno/README.md) — admission-time
  counterparts of the RBAC rules, with an honest map of what the upstream
  Kyverno library already covers and the two policies we're contributing.
- The dashboard's `/docs` page — in-app copy of the extension standard.
