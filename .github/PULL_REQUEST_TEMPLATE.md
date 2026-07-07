## What this changes

Brief description. Link the issue it closes: `Closes #`.

## Type

- [ ] New detection rule / finding source
- [ ] Bug fix
- [ ] Feature
- [ ] Docs
- [ ] Refactor / chore

## Checklist

- [ ] `make test` passes
- [ ] Added/updated tests for the behavior change
- [ ] New rule ships with a remediation and a **verified** benchmark citation
      (exact CIS Kubernetes Benchmark version + ID, or a primary source — not
      an invented ID)
- [ ] Added a fixture to `hack/dev/rbac-fixtures.yaml` if it's a new rule
- [ ] Docs updated ([docs/rbac-rules.md](../docs/rbac-rules.md) for a new rule)
- [ ] Conventional commit messages

## How you verified it

What you ran and what you saw — e.g. `make setup-dev && make scan` output, or
the specific test.
