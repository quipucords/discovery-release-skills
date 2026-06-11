---
name: query-errata-advisory
description: >
  Query the Red Hat Errata Advisory API for a single advisory to get its CVE IDs and
  fixed package NVRs (Name-Version-Release). Use when you have an advisory ID from any
  source (catalog, prograde, or JIRA) and need to know exactly which CVEs it fixes and
  what package versions contain the fix.
compatibility: >
  Kerberos authentication required. Run `kinit <username>@YOUR_KERBEROS_REALM` before use.
  Red Hat internal network access required. uv required. curl must be available.
metadata:
  topic: cve-tracking
---

## When to use

Use this skill to enrich advisory references from any source with:
- **CVE IDs** extracted from description, linked Bugzilla bugs, and linked JIRA issues
- **Fixed package NVRs** (the exact package versions that resolve the CVEs)
- **RPM lists by architecture** for each build

Call once per unique advisory ID. Advisory IDs may come from:
- `parse-prograde-advisories` output (`advisory_id`, numeric)
- `query-redhat-catalog` output (`advisory_id`, RHSA format like `RHSA-2026:12441`)
- JIRA issue descriptions

All formats are accepted: `165721`, `RHSA-165721`, `RHSA-2026:6923`.

## Prerequisites

Valid Kerberos ticket:
```bash
kinit --keychain -V <username>@YOUR_KERBEROS_REALM  # macOS keychain
klist -s && echo "ticket valid" || echo "need to kinit"
```

## Invocation

```bash
# Query by numeric ID (from prograde)
uv run .claude/skills/query-errata-advisory/scripts/query-errata-advisory.py 165721 > errata-165721.json

# Query by RHSA designation (from catalog)
uv run .claude/skills/query-errata-advisory/scripts/query-errata-advisory.py "RHSA-2026:12441" > errata-RHSA-2026-12441.json

# Batch: query all advisory IDs from catalog output
jq -r '.cves[].advisory_id | select(.)' catalog.json | sort -u | while read id; do
  safe="${id//[^a-zA-Z0-9]/-}"
  uv run .claude/skills/query-errata-advisory/scripts/query-errata-advisory.py "$id" > "errata-${safe}.json"
done

# See all options
uv run .claude/skills/query-errata-advisory/scripts/query-errata-advisory.py --help
```

## Output

JSON to stdout (one object per invocation):
- `cve_ids`: all CVEs fixed by this advisory (from description, Bugzilla, and JIRA)
- `releases`: fixed package builds keyed by RHEL release, each build including:
  - `nvr`: full Name-Version-Release string
  - `name`, `version`, `release`, `epoch`: parsed components
  - `build_id`: Brew build ID (links to [internal-brew-host])
  - `rpms_by_arch`: RPM filenames grouped by architecture

## Pipeline

One errata output file per advisory. Pass all of them together to `merge-cve-data`:

```bash
uv run .claude/skills/merge-cve-data/scripts/merge-cve-data.py \
  --catalog catalog.json \
  --prograde prograde-advisories.json \
  --errata errata-*.json \
  --jira jira.json
```
