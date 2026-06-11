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
# From stdin (piped from query-gmail)
uv run .claude/skills/query-gmail/scripts/query-gmail.py --label "alerts/prograde" --since "2026-05-01" \
  | uv run .claude/skills/parse-prograde-advisories/scripts/parse-prograde-advisories.py > prograde-advisories.json

# From a saved file
uv run .claude/skills/parse-prograde-advisories/scripts/parse-prograde-advisories.py prograde-emails.json > prograde-advisories.json

# Explicitly from stdin
cat prograde-emails.json | uv run .claude/skills/parse-prograde-advisories/scripts/parse-prograde-advisories.py -

# See all options
uv run .claude/skills/parse-prograde-advisories/scripts/parse-prograde-advisories.py --help
```

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

Extract advisory IDs for the next step:

```bash
jq -r '.advisories[].advisory_id' prograde-advisories.json | sort -u | while read id; do
  uv run .claude/skills/query-errata-advisory/scripts/query-errata-advisory.py "$id" > "errata-${id}.json"
done
```
