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

### Step 1 — Gather options from the user

Before running anything, ask the user the following two questions. Use their
answers to build the arguments for `collect-sources.py` in Phase 1.

**Question 1 — Prograde emails and date range:**
Ask the user whether to include Prograde advisory emails from Gmail. Not all
users receive these emails or have Gmail configured. If they do, also ask how
far back to query. Pass `--skip-gmail` to `collect-sources.py` if skipping;
pass `--since-last-release` to auto-detect the last downstream release date;
pass `--since YYYY-MM-DD` if a custom date is given (default is 90 days ago).

Options to present:
- **Since last downstream release** — query catalog for when the latest discovery images were published, use that date; pass `--since-last-release`
- **Last 90 days (default)** — query Gmail for Prograde emails from the last 90 days
- **Custom date** — query Gmail from a specific date (ask for the date)
- **Use provided json file** — skip Gmail but read `cve-data/prograde-emails.json` from disk; pass `--use-provided-prograde`. Use when a teammate has already exported the file.
- **Skip Prograde emails** — omit Gmail entirely; use `--skip-gmail` flag

**Question 2 — Red Hat Catalog image tags:**
The catalog query defaults to the latest published tag for both
`discovery-server` and `discovery-ui`. Ask whether the user wants to query
specific tags instead. If yes, ask for the tag for each container separately
(they may differ). Pass non-default tags as `--server-tag TAG` and/or
`--ui-tag TAG` to `collect-sources.py`.

Once you have the answers, proceed with Step 2.

### Step 2 — Navigate to project root and validate prerequisites

```bash
python3 .claude/skills/check-location.py
```

> **Always use relative paths** when invoking scripts in this skill — never
> absolute paths. The allowlist that permits these commands matches the
> relative form `python3 .claude/skills/...` only.

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

Pass the options gathered in Step 1. Omit any flag whose value is the default:

```bash
python3 .claude/skills/query-all-cves/scripts/collect-sources.py \
  [--since YYYY-MM-DD | --since-last-release] \
  [--server-tag TAG] \
  [--ui-tag TAG]
```

When `--server-tag` or `--ui-tag` are provided, the catalog is queried once
per container and results are merged automatically before the parallel Gmail
and JIRA queries run.

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
