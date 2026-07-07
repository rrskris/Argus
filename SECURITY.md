# Security policy

## Reporting a vulnerability

Argus is a security tool, so we take issues in Argus itself seriously.

**Do not open a public issue for a security vulnerability.** Instead, use
GitHub's private [security advisory
reporting](https://github.com/rrskris/Argus/security/advisories/new), or email
the maintainer at rrskris@gmail.com with:

- a description of the issue and its impact,
- steps to reproduce,
- affected version/commit.

We'll acknowledge within a few days and work with you on a fix and
coordinated disclosure.

## Scope

Most relevant to Argus's own posture:

- The control plane handles cluster credentials and bearer tokens — issues in
  auth, token handling, or credential storage are in scope.
- Argus requests **read-only** cluster access and applies no changes; a code
  path that acquires write access to a scanned cluster is a bug, report it.
- The CLI and API run untrusted manifest/feed input through parsers — parser
  crashes or injection are in scope.
