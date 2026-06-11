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
- Valid Kerberos ticket — for `query-errata-advisory`
- `uv` installed

## Orchestration

> **Important — stdout/stderr separation:** All scripts in this pipeline write JSON
> exclusively to stdout and progress logs to stderr. **Never redirect stderr into a
> data file** (never use `2>&1` when writing to `.json` files). Doing so produces
> invalid JSON that will silently corrupt downstream steps.

### Step 0 — Validate prerequisites

Run these checks first, before any data collection. If any check fails, stop and
resolve the issue before continuing — otherwise Phase 1 work may be wasted.

```bash
root=$(git rev-parse --show-toplevel 2>/dev/null)
if [ -z "$root" ]; then
  d=$PWD
  while [ "$d" != "/" ]; do
    [ -d "$d/.claude/skills" ] && root=$d && break
    d=$(dirname "$d")
  done
fi
[ -n "$root" ] && cd "$root" || { echo "Error: cannot find project root"; exit 1; }
mkdir -p cve-data

# Check Kerberos ticket (required for query-errata-advisory in Phase 2)
klist -s && echo "Kerberos ticket valid" || { echo "Error: no valid Kerberos ticket. Run: kinit --keychain -V <username>@YOUR_KERBEROS_REALM"; exit 1; }

# Check JIRA credentials (required for query-jira-cves in Phase 1)
[ -n "$JIRA_EMAIL" ] && [ -n "$JIRA_API_TOKEN" ] || { echo "Error: JIRA_EMAIL and JIRA_API_TOKEN must be set. See project README."; exit 1; }
```

### Phase 1 — Collect from all sources (run in parallel)

Run all three source queries concurrently. Use background shell jobs (`&`) and `wait`
to parallelize. Redirect **only stdout** to each data file — do not use `2>&1`.

```bash
SINCE=$(python3 -c "import datetime; print((datetime.date.today() - datetime.timedelta(days=90)).isoformat())")

uv run .claude/skills/query-redhat-catalog/scripts/query-redhat-catalog.py \
  > cve-data/catalog.json &
PID_CATALOG=$!

uv run .claude/skills/query-gmail/scripts/query-gmail.py \
  --label "alerts/prograde" --since "$SINCE" \
  > cve-data/prograde-emails.json &
PID_GMAIL=$!

uv run .claude/skills/query-jira-cves/scripts/query-jira-cves.py \
  --summary-contains "CVE" \
  > cve-data/jira.json &
PID_JIRA=$!

wait $PID_CATALOG $PID_GMAIL $PID_JIRA
```

After `wait`, validate that each output file is non-empty and contains valid JSON before
continuing — a corrupted file will silently produce wrong results at merge time:

```bash
for f in cve-data/catalog.json cve-data/prograde-emails.json cve-data/jira.json; do
  python3 -c "import json,sys; json.load(open('$f'))" \
    && echo "$f OK" \
    || { echo "Error: $f is not valid JSON — do not use 2>&1 when redirecting output"; exit 1; }
done
```

Then parse the Prograde emails:

```bash
uv run .claude/skills/parse-prograde-advisories/scripts/parse-prograde-advisories.py \
  cve-data/prograde-emails.json > cve-data/prograde-advisories.json
```

### Phase 2 — Enrich with errata (run in parallel)

Extract all unique advisory IDs from both catalog and prograde sources. Note that the
two sources use different ID formats — catalog uses RHSA-format (e.g. `RHSA-2026:12441`)
and prograde uses numeric IDs (e.g. `165721`). Both formats are accepted by
`query-errata-advisory`. Deduplicate before querying to avoid redundant API calls.

```bash
{ jq -r '.cves[].advisory_id | select(.)' cve-data/catalog.json
  jq -r '.advisories[].advisory_id | select(.)' cve-data/prograde-advisories.json
} | sort -u > cve-data/advisory-ids.txt

echo "Querying $(wc -l < cve-data/advisory-ids.txt) unique advisory IDs..."

while IFS= read -r id; do
  safe="${id//[^a-zA-Z0-9]/-}"
  uv run .claude/skills/query-errata-advisory/scripts/query-errata-advisory.py "$id" \
    > "cve-data/errata-${safe}.json" &
done < cve-data/advisory-ids.txt
wait
```

### Phase 3 — Merge

```bash
uv run .claude/skills/merge-cve-data/scripts/merge-cve-data.py \
  --catalog cve-data/catalog.json \
  --prograde cve-data/prograde-advisories.json \
  --errata cve-data/errata-*.json \
  --jira cve-data/jira.json \
  > cve-data/unified-cves.json

echo "Done. Summary:"
python3 -c "
import json
d = json.load(open('cve-data/unified-cves.json'))
s = d['summary']
print(f\"  Total CVEs: {s['total_cves']}\")
print(f\"  Fix available: {s['fix_available']}\")
print(f\"  Sources: {', '.join(s['sources_used'])}\")
"
```

## Dependency graph

```
query-gmail ──→ parse-prograde-advisories ──┐
                                            ├──→ query-errata-advisory (per advisory ID) ──┐
query-redhat-catalog ───────────────────────┘                                               ├──→ merge-cve-data
query-jira-cves ────────────────────────────────────────────────────────────────────────────┘
```

## Output

`cve-data/unified-cves.json` — see `merge-cve-data` for the full output schema.
