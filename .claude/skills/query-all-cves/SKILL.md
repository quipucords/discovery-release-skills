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

All complex operations are encapsulated in helper scripts under
`.claude/skills/query-all-cves/scripts/`. Each step below is a single
`python3 script.py` call — no inline Python, no shell wildcards, no background
job syntax. This keeps each command simple and avoids approval prompts.

### Step 0 — Navigate to project root and validate prerequisites

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
```

Then check all credentials before doing any work — failures here are caught before
any long-running collection begins:

```bash
python3 .claude/skills/query-all-cves/scripts/check-prerequisites.py
```

### Step 1 — Clean stale errata files

```bash
python3 .claude/skills/query-all-cves/scripts/clean-cve-data.py
```

### Phase 1 — Collect from all sources in parallel

Runs catalog, Gmail, and JIRA queries concurrently via `subprocess.Popen`.
Stdout is redirected to data files inside the script — stderr always goes to
the terminal. The `2>&1` corruption risk is eliminated.

```bash
python3 .claude/skills/query-all-cves/scripts/collect-sources.py
```

### Step — Validate Phase 1 outputs

Catches JSON corruption before any downstream work is wasted:

```bash
python3 .claude/skills/query-all-cves/scripts/validate-json-files.py \
  cve-data/catalog.json cve-data/prograde-emails.json cve-data/jira.json
```

### Step — Parse Prograde emails

```bash
python3 .claude/skills/query-all-cves/scripts/parse-prograde.py
```

### Step — Extract and deduplicate advisory IDs

Reads both catalog and prograde sources; deduplicates across their different
ID formats (RHSA-format vs numeric); writes `cve-data/advisory-ids.txt`:

```bash
python3 .claude/skills/query-all-cves/scripts/extract-advisory-ids.py
```

### Phase 2 — Query all errata in parallel

```bash
python3 .claude/skills/query-all-cves/scripts/query-all-errata.py
```

### Phase 3 — Merge all sources

Resolves `cve-data/errata-*.json` via Python glob internally — no shell
wildcard expansion needed:

```bash
python3 .claude/skills/query-all-cves/scripts/run-merge.py
```

### Step — Print summary

```bash
python3 .claude/skills/query-all-cves/scripts/print-summary.py
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
