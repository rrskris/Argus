---
name: Rule request
about: Propose a new detection rule (RBAC misconfiguration, CVE source, or other finding)
title: "[rule] "
labels: ["rule-request", "help wanted"]
---

## What should Argus detect?

Describe the misconfiguration or risk, and the Kubernetes objects it shows up
in (Role/ClusterRole rule, binding, workload spec, etc.).

## Why it matters

What's the blast radius if this goes unnoticed? What can an attacker or a
compromised workload do with it?

## Benchmark / standard mapping (if any)

Cite the exact control if one exists — e.g. `CIS Kubernetes Benchmark v1.12.0
5.1.x`, an OWASP Kubernetes Top 10 item, or the Kubernetes RBAC Good Practices
doc. Leave blank if you're not sure; we'll verify before it ships.

## Suggested severity

CRITICAL / HIGH / MEDIUM / LOW, and a sentence on why.

## Example trigger

A snippet of the manifest that should be flagged, if you have one.
