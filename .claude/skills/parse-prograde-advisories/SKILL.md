---
name: parse-prograde-advisories
description: >
  Parse Prograde CVE notification emails to extract advisory links, synopsis, severity,
  and affected container names. Use when you have Prograde email JSON (from query-gmail)
  and need advisory IDs to feed into query-errata-advisory.
compatibility: uv required. beautifulsoup4 installed automatically via PEP 723.
metadata:
  topic: cve-tracking
---

## When to use

Use this skill **after query-gmail** to extract structured advisory data from Prograde
email bodies. Prograde emails contain HTML tables listing affected containers and links
to errata advisories — this skill parses that HTML and produces clean JSON.

The output `advisory_id` field is the key link to `query-errata-advisory`, which
retrieves the actual CVE IDs and fixed package NVRs for each advisory.

## Invocation

```bash
# From a saved file (output of query-gmail skill)
uv run .claude/skills/parse-prograde-advisories/scripts/parse-prograde-advisories.py cve-data/prograde-emails.json > cve-data/prograde-advisories.json

# Explicitly from stdin
cat cve-data/prograde-emails.json | uv run .claude/skills/parse-prograde-advisories/scripts/parse-prograde-advisories.py - > cve-data/prograde-advisories.json

# See all options
uv run .claude/skills/parse-prograde-advisories/scripts/parse-prograde-advisories.py --help
```

When invoking as part of the pipeline, first invoke the `query-gmail` skill and save
its output, then pass that file to this skill.

## Output

JSON to stdout: `{"advisories": [{...}, ...]}` where each advisory contains:
`message_id`, `subject`, `date`, `advisory_link`, `advisory_id` (numeric),
`advisory_synopsis`, `advisory_security_impact`, `affected_containers`.

Note: `advisory_id` here is a **numeric Errata ID** (e.g. `"165721"`), not an RHSA
designation. Pass it to `query-errata-advisory` to get CVE IDs and fixed packages.

## Pipeline

```
query-gmail → parse-prograde-advisories → query-errata-advisory → merge-cve-data
```

This skill is a data source. Its output `advisory_id` fields are passed to the
`query-errata-advisory` skill (once per unique ID) to retrieve CVE IDs and fixed
package NVRs. The full pipeline is orchestrated by the `merge-cve-data` skill.
