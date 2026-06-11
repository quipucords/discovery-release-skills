---
name: query-all-cves
description: >
  Orchestrate the full CVE data collection pipeline: query all sources (Red Hat Catalog,
  Prograde emails, JIRA) in parallel, enrich each advisory with errata data, and merge
  into a single unified report. Use when you need a complete, up-to-date picture of CVEs
  affecting the Discovery container images.
compatibility: >
  Requires the prerequisites of all sub-skills combined: Gmail OAuth credentials, JIRA_EMAIL
  and JIRA_API_TOKEN environment variables, valid Kerberos ticket (kinit), and uv installed.
  See individual skill docs and the project README for setup details.
metadata:
  topic: cve-tracking
---

## When to use

Use this skill as the primary entry point for CVE data collection. It drives the full
pipeline and produces `cve-data/unified-cves.json`.

For partial runs (e.g., catalog data only, no Gmail or JIRA setup), invoke the individual
source skills directly and then call `merge-cve-data`.

## Prerequisites

Combined prerequisites of all sub-skills:

- Gmail OAuth credentials at `~/.config/gmail/credentials.json` — for `query-gmail`
- `JIRA_EMAIL` and `JIRA_API_TOKEN` environment variables — for `query-jira-cves`
  (see project README for how to set these via Claude Code `settings.json`)
- Valid Kerberos ticket — for `query-errata-advisory`:
  ```bash
  klist -s && echo "ticket valid" || kinit --keychain -V <username>@YOUR_KERBEROS_REALM
  ```
- `uv` installed

## Orchestration

Invoke the following skills in the order below. Steps within each phase are independent
and should be run in parallel where possible.

**Phase 1 — Collect from all sources (run concurrently):**

1. Invoke `query-redhat-catalog` → `cve-data/catalog.json`
2. Invoke `query-gmail`, then `parse-prograde-advisories` → `cve-data/prograde-advisories.json`
3. Invoke `query-jira-cves` → `cve-data/jira.json`

**Phase 2 — Enrich with errata (parallelizable):**

Extract all unique advisory IDs from `cve-data/catalog.json` and
`cve-data/prograde-advisories.json`. Invoke `query-errata-advisory` once per ID —
these calls are independent and can be parallelized.

**Phase 3 — Merge:**

Invoke `merge-cve-data` → `cve-data/unified-cves.json`.

## Dependency graph

```
query-gmail ──→ parse-prograde-advisories ──┐
                                            ├──→ query-errata-advisory (per advisory ID) ──┐
query-redhat-catalog ───────────────────────┘                                               ├──→ merge-cve-data
query-jira-cves ────────────────────────────────────────────────────────────────────────────┘
```

## Output

`cve-data/unified-cves.json` — see `merge-cve-data` for the full output schema.
