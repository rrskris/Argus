# Security policy

## Supported versions

| Version | Supported |
|---|---|
| latest release (currently 1.1.x) | ✅ |
| `main` (`:edge` images) | ✅ best-effort |
| older releases | ❌ — upgrade to the latest release |

Security fixes land on `main` and ship in the next release; we do not backport
to older versions at the project's current size.

## Reporting a vulnerability

Kaaval is a security tool, so we take issues in Kaaval itself seriously.

**Do not open a public issue for a security vulnerability.** Instead, use
GitHub's private [security advisory
reporting](https://github.com/kaaval/kaaval/security/advisories/new), or email
the maintainer at rrskris@gmail.com with:

- a description of the issue and its impact,
- steps to reproduce,
- affected version/commit.

We'll acknowledge within a few days and work with you on a fix and
coordinated disclosure.

## Scope

Most relevant to Kaaval's own posture:

- The control plane handles cluster credentials and bearer tokens — issues in
  auth, token handling, or credential storage are in scope.
- Kaaval requests **read-only** cluster access and applies no changes; a code
  path that acquires write access to a scanned cluster is a bug, report it.
- The CLI and API run untrusted manifest/feed input through parsers — parser
  crashes or injection are in scope.
