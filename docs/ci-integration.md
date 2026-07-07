# CI/CD integration

Argus gates pipelines on the **Contextual Risk Score**, not a flat severity
threshold. The same wildcard ClusterRole that hard-fails a production/PCI
pipeline can pass with a warning in a dev pipeline — because the committed
risk context says so. Every scanner can `--fail-on HIGH`; this is the part
they can't do.

Two integration modes, one CLI:

- **Shift-left (`--manifests`)** — scan RBAC YAML in the repo (or
  `helm template` output) at PR time, before anything reaches a cluster. No
  cluster credentials needed.
- **Live (`--kubeconfig`)** — scan a real cluster's RBAC state, e.g. after a
  deploy or on a schedule, using a read-only CI service account.

Both run the exact same rule engine and scoring code the Argus server uses
(`evaluate_rbac_findings()` + `compute_contextual_score()` +
`build_remediation()`), with no database, auth, or running control plane.

## The CLI

```bash
cd control-plane
pip install -r requirements.txt

# shift-left: scan manifests in ./k8s
python -m app.cli scan rbac --manifests ./k8s/ \
    --context-file argus.yaml --fail-on-score 20 --output json

# live: scan the cluster a kubeconfig points at
python -m app.cli scan rbac --kubeconfig ./ci-kubeconfig --fail-on-severity HIGH
```

Or via the container image (the control-plane image includes the CLI):

```bash
docker build -t argus-control-plane control-plane/
docker run --rm -v "$PWD/k8s:/scan" -v "$PWD/argus.yaml:/scan/argus.yaml" \
    argus-control-plane \
    python -m app.cli scan rbac --manifests /scan --context-file /scan/argus.yaml --fail-on-score 20
```

### Flags

| Flag | Meaning |
|---|---|
| `--manifests PATH` | Scan RBAC YAML at PATH (file or directory, recursive; handles multi-doc YAML and `kind: List`) |
| `--kubeconfig PATH` | Scan the live cluster this kubeconfig points at (falls back to `$KUBECONFIG` / in-cluster / default kubeconfig if omitted) |
| `--context-file PATH` | `argus.yaml` risk context (see below). Without it, defaults apply (production/internal/internal, no compliance scope) and a warning is printed |
| `--fail-on-score N` | Exit 1 if any finding's contextual score ≥ N |
| `--fail-on-severity SEV` | Exit 1 if any finding is at/above SEV (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`, case-insensitive) |
| `--output table\|json` | Human table (default) or full JSON including remediation objects and score factors |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan ran; no finding at/above the configured thresholds (or no thresholds set) |
| 1 | Gate failed — at least one finding at/above a threshold |
| 2 | Usage error (bad path, invalid context value, bad flag) |

### `argus.yaml` — risk context as code

Commit this next to your manifests. It is the input to the scoring formula
(see [contextual-risk-score.md](contextual-risk-score.md)) and it is
reviewable in PRs like everything else:

```yaml
environment: production            # production | staging | dev
data_classification: pii           # public | internal | pii | financial | phi
compliance_scope: [PCI-DSS]        # any of PCI-DSS, HIPAA, SOC2 (or empty)
exposure: internet-facing          # internet-facing | internal
fail_on_score: 20                  # optional gate; CLI flags override
fail_on_severity: HIGH             # optional gate; CLI flags override
```

A sensible pattern: the dev overlay's `argus.yaml` says `environment: dev`
with a high (or no) threshold; the production overlay says
`environment: production` with a strict one. Same manifests, different gates
— by declared risk, not by pipeline copy-paste.

### Shift-left mode limitation

Findings are evaluated per (role, binding) pair. A binding that references a
role **not present in the scanned manifests** (e.g. the built-in
`cluster-admin` ClusterRole) is skipped in `--manifests` mode because there
are no rules to evaluate — live mode catches those, since the cluster knows
the role. Run both: manifests at PR time, live post-deploy.

## GitHub Actions

Use the composite action shipped in this repo:

```yaml
jobs:
  rbac-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rrskris/Argus/.github/actions/argus-scan@main
        with:
          manifests: k8s/
          context-file: k8s/argus.yaml
          fail-on-score: "20"
```

Inputs mirror the CLI flags (`manifests`, `kubeconfig`, `context-file`,
`fail-on-score`, `fail-on-severity`, `output`, plus `argus-ref` to pin an
Argus version). For live-cluster scans in CI, write the service-account
kubeconfig from a secret first:

```yaml
      - run: echo "${{ secrets.CI_KUBECONFIG }}" > ci-kubeconfig
      - uses: rrskris/Argus/.github/actions/argus-scan@main
        with:
          kubeconfig: ci-kubeconfig
          context-file: argus.yaml
          fail-on-severity: CRITICAL
```

## GitLab CI

```yaml
argus-rbac-scan:
  stage: test
  image: python:3.12-slim
  script:
    - git clone --depth 1 https://github.com/rrskris/Argus /argus
    - pip install -q -r /argus/control-plane/requirements.txt
    - cd /argus/control-plane
    - python -m app.cli scan rbac
        --manifests "$CI_PROJECT_DIR/k8s"
        --context-file "$CI_PROJECT_DIR/k8s/argus.yaml"
        --fail-on-score 20 --output json | tee "$CI_PROJECT_DIR/argus-report.json"
  artifacts:
    when: always
    paths: [argus-report.json]
```

## Jenkins (declarative)

```groovy
stage('Argus RBAC scan') {
    steps {
        sh '''
            git clone --depth 1 https://github.com/rrskris/Argus argus
            pip install -q -r argus/control-plane/requirements.txt
            cd argus/control-plane
            python -m app.cli scan rbac \
                --manifests "$WORKSPACE/k8s" \
                --context-file "$WORKSPACE/k8s/argus.yaml" \
                --fail-on-score 20
        '''
    }
}
```

## Argo CD — verify after deploy (PostSync hook)

GitOps closes the loop with a live scan right after sync. The hook Job fails
the sync's health if the gate trips:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: argus-postsync-scan
  annotations:
    argocd.argoproj.io/hook: PostSync
    argocd.argoproj.io/hook-delete-policy: HookSucceeded
spec:
  template:
    spec:
      serviceAccountName: argus-scanner   # read-only RBAC viewer, see below
      restartPolicy: Never
      containers:
        - name: argus
          image: <your-registry>/argus-control-plane:latest
          command: ["python", "-m", "app.cli", "scan", "rbac",
                    "--fail-on-severity", "CRITICAL"]
```

Running in-cluster with a ServiceAccount needs only read access to RBAC
objects:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: argus-scanner
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "clusterroles", "rolebindings", "clusterrolebindings"]
    verbs: ["get", "list"]
```

(Yes — Argus's own scanner role is intentionally narrow enough that Argus
would not flag it.)

## Consuming the JSON in other tooling

`--output json` emits the full result: per-finding `contextual_score`,
`score_factors` (every multiplier, explained), and the `remediation` object
(`action`, `why_it_matters`, `benchmark_refs` with CIS Kubernetes Benchmark
v1.12.0 control IDs, `compliance_note`, `audit_note`). Pipe it to `jq`, post
it as a PR comment, or attach it as a build artifact — the explanation
travels with the finding.

Planned next (see the roadmap): SARIF output for the GitHub Security tab,
JUnit XML for GitLab/Jenkins test panes, Prometheus metrics + scan-diff for
SRE alerting on *new* findings only, and a Helm chart for one-line install.
## GitHub Actions — SARIF upload to Security tab

\`\`\`yaml
- name: Run Argus RBAC scan
  run: |
    python -m app.cli scan rbac \
      --manifests ./k8s/ \
      --context-file argus.yaml \
      --output sarif > results.sarif

- name: Upload SARIF to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
\`\`\`