---
name: query-redhat-catalog
description: >
  Query the Red Hat Container Catalog for CVEs affecting the published Discovery
  container images. Use when you need the authoritative list of CVEs in the currently
  published downstream images, with vulnerable package versions and advisory IDs.
compatibility: >
  Internet access required (catalog.redhat.com public API). No authentication needed.
  uv required. httpx installed automatically via PEP 723.
metadata:
  topic: cve-tracking
---

## When to use

Use this skill to get the ground truth about **what CVEs exist in the currently published
downstream container images** (`registry.redhat.io/discovery/...`). This is the highest
quality source for:
- Which packages are currently at vulnerable versions in the published image
- Which RHSA advisory fixes each CVE
- Whether the vulnerability has been published and is publicly visible

The output `advisory_id` field can be passed directly to `query-errata-advisory` to get
the fixed package NVRs.

Note: this reflects the **published downstream image**, not the upstream Quay.io build.
A new upstream release will not appear here until it is published downstream.

## Invocation

```bash
# Query both containers (default)
uv run .claude/skills/query-redhat-catalog/scripts/query-redhat-catalog.py > catalog.json

# Query only the server container
uv run .claude/skills/query-redhat-catalog/scripts/query-redhat-catalog.py --container discovery-server > catalog.json

# Query a specific published version tag
uv run .claude/skills/query-redhat-catalog/scripts/query-redhat-catalog.py --tag 2.5.1 > catalog.json

# See all options
uv run .claude/skills/query-redhat-catalog/scripts/query-redhat-catalog.py --help
```

## Output

JSON to stdout: `{"total": N, "cves": [{...}, ...]}` where each CVE contains:
`container`, `image_name`, `cve_id`, `cve_link`, `severity`, `advisory_id`,
`advisory_link`, `creation_date`, `affected_packages` (with name/version/arch),
`rpm_nvras` (full NVRA strings of vulnerable packages).

## Pipeline

```
query-redhat-catalog → query-errata-advisory (per advisory_id) → merge-cve-data
```

Batch-query errata for all advisories found in catalog output:

```bash
uv run .claude/skills/query-redhat-catalog/scripts/query-redhat-catalog.py > catalog.json

jq -r '.cves[].advisory_id | select(.)' catalog.json | sort -u | while read id; do
  safe="${id//[^a-zA-Z0-9]/-}"
  uv run .claude/skills/query-errata-advisory/scripts/query-errata-advisory.py "$id" > "errata-${safe}.json"
done
```
