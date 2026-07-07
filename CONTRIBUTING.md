# Contributing to Argus

Argus is a self-hosted Kubernetes security scanner built on one principle: a
finding is only useful once it's tied to *your* environment and comes with a
concrete next step. Contributions that push in that direction — better
detection, better context, better remediation — are very welcome.

New to the project? The fastest way in is a **rule request** or a **new
detection rule** (see below) — they're self-contained and the testbed lets
you verify them in seconds.

## Get a vulnerable cluster running in under two minutes

You need Docker, [`kind`](https://kind.sigs.k8s.io/), `kubectl`, and Python
3.12. Then:

```bash
make setup-dev        # kind cluster + planted RBAC misconfigurations
make scan             # run the RBAC scanner against it — see findings ranked
make teardown-dev     # tear it down when you're done
```

`make setup-dev` provisions a throwaway cluster preloaded with deliberately
insecure RBAC objects (`hack/dev/rbac-fixtures.yaml`) — a safe target you can
break and rebuild freely. Run `make help` for the full target list.

For the shift-left path (no cluster needed at all):

```bash
make scan-manifests   # scan the fixture YAML directly
```

## Run the tests

```bash
make db               # throwaway Postgres
make test             # control-plane test suite
make db-stop
```

Tests are pure-function where possible (`control-plane/tests/`) — the RBAC
rules, scoring, and remediation all have unit coverage that needs neither a
cluster nor a database. Please add a test with any behavior change.

## The two highest-value contributions

### 1. A new detection rule

This is the most requested and most self-contained contribution. A rule maps
a Kubernetes misconfiguration to the Contextual Risk Score and a remediation.
The pattern, all in `control-plane/app/`:

1. Add a detector predicate in `rbac_service.py` (e.g. `_grants_something`),
   and emit a `risk` dict from `_evaluate_role_risks()` (or the binding loop)
   with a new `rule_type`, `severity`, and `detail`.
2. Add the mapping in `remediation.py`: a `_CIS_REFS` entry (use the **exact,
   verified** benchmark control ID — see below) and an `_RBAC_ACTIONS` entry
   with the concrete `kubectl` fix.
3. Add a fixture to `hack/dev/rbac-fixtures.yaml` and a unit test in
   `tests/test_rbac_service.py`.

The existing rules ([docs/rbac-rules.md](docs/rbac-rules.md)) are your
templates. Nothing ships detection-only — a rule without a remediation and a
benchmark reference isn't done.

**Verify benchmark citations.** CIS Kubernetes Benchmark control IDs shift
between versions. Cite the exact version and ID (`CIS Kubernetes Benchmark
v1.12.0`), and if no control covers your rule, cite the primary source
(Kubernetes RBAC Good Practices, OWASP Kubernetes Top 10) rather than
inventing an ID. A wrong compliance citation is worse than none.

### 2. A new finding source

Argus's moat is the scoring/explanation layer, not the detection engine, so
the more sources feed it the better. The pattern: write a pure adapter that
emits the existing finding dict shape, and everything downstream
(`compute_contextual_score()`, `build_remediation()`, PDF, dashboard) works
unmodified. See [docs/trivy-grype-integration.md](docs/trivy-grype-integration.md)
for the worked design.

## Workflow

1. Open (or comment on) an issue first for anything non-trivial, so we don't
   duplicate work. Look for [`good first issue`](https://github.com/rrskris/Argus/labels/good%20first%20issue)
   and [`help wanted`](https://github.com/rrskris/Argus/labels/help%20wanted).
2. Branch off `main`. Keep PRs focused — one rule, one source, one fix.
3. `make test` passes; add coverage for new behavior.
4. Conventional commit messages (`feat:`, `fix:`, `docs:`, `chore:`) — see the
   existing history.
5. Open a PR with the template filled in.

## Project layout

| Path | What it is |
|---|---|
| `control-plane/` | FastAPI backend: scanning, scoring, remediation, CLI, PDF |
| `dashboard/` | Next.js frontend |
| `policies/kyverno/` | Admission-time counterparts of the RBAC rules |
| `docs/` | Architecture, rule catalog, scoring, API, CI integration |
| `hack/dev/` | Developer testbed fixtures |
| `deploy/` | docker-compose stack |

More detail in [docs/architecture.md](docs/architecture.md).

## Scope and philosophy

Argus recommends fixes; it does not apply them (read-only cluster access, no
write verbs). Detection without guidance is noise — every finding should
explain *why* it matters and *what to do*. If a change moves away from that,
it's probably out of scope; open an issue to discuss before building.

## License

By contributing you agree your contributions are licensed under the
[Apache License 2.0](LICENSE).
