---
name: verify-cves-in-source
description: >
  Check source code repositories (quipucords / quipucords-ui) to determine whether
  non-RPM packages (npm, pip) flagged as CVE-affected are at fixed versions. Supplements
  verify-cves-in-builds for CVEs that RPM scanning left as "unknown". Writes
  cve-data/verified-cves-source.json and optionally re-runs compare-cve-results.py
  to promote resolved unknowns to a real delta.
compatibility: >
  cve-data/unified-cves.json must exist (run query-all-cves first). git must be in PATH.
  The source repos are cloned automatically if they do not exist at the configured paths.
  SSH key must be available for cloning from GitHub if repos are absent.
metadata:
  topic: cve-tracking
---

## When to use

Use this skill after `verify-cves-in-builds` has produced `verified-cves-downstream.json`
and `verified-cves-upstream.json`. It fills in the gaps for CVEs marked **UNKNOWN** —
those where no RPM package name was available because the vulnerable component is a
non-RPM dependency (e.g. axios from npm, or a pip package).

The skill reads source-code lockfiles to check whether upstream has already bumped the
package past the minimum fixed version published in the JIRA advisory. When it has, the
CVE is promoted from `unknown` → `fixed_upstream_not_downstream` in the comparison report.

## Prerequisites

- `cve-data/unified-cves.json` must exist — run `query-all-cves` first
- `cve-data/verified-cves-downstream.json` and `cve-data/verified-cves-upstream.json`
  must exist — run `verify-cves-in-builds` first (compare mode)
- `git` must be installed and in PATH
- If the repos are not yet cloned, an SSH key for GitHub must be available

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `QUIPUCORDS_SERVER_REPO_PATH` | `../quipucords` | Local path to quipucords repo |
| `QUIPUCORDS_UI_REPO_PATH` | `../quipucords-ui` | Local path to quipucords-ui repo |
| `QUIPUCORDS_SERVER_REPO_URL` | `git@github.com:quipucords/quipucords.git` | Clone URL (only used when path is absent) |
| `QUIPUCORDS_UI_REPO_URL` | `git@github.com:quipucords/quipucords-ui.git` | Clone URL (only used when path is absent) |

## Orchestration

### Step 1 — Gather commitish options

```
AskUserQuestion({
  "questions": [
    {
      "question": "What commitish should be checked for the server repo (quipucords)?",
      "header": "Server commitish",
      "multiSelect": false,
      "options": [
        {"label": "main",   "description": "HEAD of the main branch after a fresh fetch"},
        {"label": "Custom", "description": "Type a tag (e.g. 2.6.0), branch name, or SHA in the Other field"}
      ]
    },
    {
      "question": "What commitish should be checked for the UI repo (quipucords-ui)?",
      "header": "UI commitish",
      "multiSelect": false,
      "options": [
        {"label": "main",   "description": "HEAD of the main branch after a fresh fetch"},
        {"label": "Custom", "description": "Type a tag (e.g. 2.6.1), branch name, or SHA in the Other field"}
      ]
    }
  ]
})
```

If the user selects "Custom" for either, use the value they type via "Other" as the commitish.

### Step 2 — Navigate to project root

```bash
python3 .claude/skills/check-location.py
```

> **Always use relative paths** when invoking scripts in this skill — never
> absolute paths. The allowlist that permits these commands matches the
> relative form `python3 .claude/skills/...` only.
>
> **IMPORTANT:** Run all script commands exactly as shown — no `2>&1`, no
> `; echo "Exit: $?"`, no shell decorators of any kind.

### Step 3 — Check source packages

Substitute SERVER_COMMITISH and UI_COMMITISH with the values from Step 1.

```bash
python3 .claude/skills/verify-cves-in-source/scripts/check-source-packages.py --server-commitish SERVER_COMMITISH --ui-commitish UI_COMMITISH --yes
```

The `--yes` flag is always passed here because the Bash tool cannot respond to interactive prompts. The script will still log warnings for any modified tracked files (and will highlight it loudly if a lockfile itself is dirty). Review the output carefully if you see such warnings.

The script will:
- Clone repos that don't exist yet
- Fetch the latest from origin
- Log a note for untracked files (safe to ignore), warn loudly for modified tracked lockfiles
- Check out the specified commitish
- Read `lockfiles/requirements.txt` (pip) and `package-lock.json` (npm)
- Compare installed versions against the fixed versions from JIRA advisory notes
- Write `cve-data/verified-cves-source.json`

### Step 4 — Re-run comparison with source data

```bash
python3 .claude/skills/verify-cves-in-builds/scripts/compare-cve-results.py --source
```

This re-generates `cve-data/comparison.json` with source results merged into
the upstream column for CVEs that were previously unknown.

### Step 5 — Regenerate HTML report

```bash
python3 .claude/skills/verify-cves-in-builds/scripts/generate-html-report.py --comparison [--package-types-file cve-data/package-types.json]
```

Tell the user:

> `cve-data/cve-report.html` has been updated. CVEs resolved via source check are shown
> with a **[src]** annotation in the upstream column. Open it in a browser:
> - macOS: `open cve-data/cve-report.html`
> - Linux: `xdg-open cve-data/cve-report.html`

## Output

`cve-data/verified-cves-source.json` — per-CVE source check results:

```json
{
  "generated_at": "...",
  "repos": {
    "pip": { "path": "../quipucords", "commitish": "main", "sha": "abc123", "lockfile": "lockfiles/requirements.txt" },
    "npm": { "path": "../quipucords-ui", "commitish": "2.6.1", "sha": "def456", "lockfile": "package-lock.json" }
  },
  "summary": { "total_checked": 11, "fixed_in_source": 3, "not_fixed_in_source": 5, "not_found": 3 },
  "cves": [
    {
      "cve_id": "CVE-2026-44486",
      "checked_containers": {
        "discovery/discovery-ui-rhel9": {
          "check_type": "source",
          "lockfile": "package-lock.json",
          "package_found": true,
          "package_name": "axios",
          "installed_version": "1.15.0",
          "minimum_fixed_version": "1.16.0",
          "is_fixed": false
        }
      }
    }
  ]
}
```

## Pipeline

```
query-all-cves → unified-cves.json
                       ↓
verify-cves-in-builds (compare mode)
  → verified-cves-downstream.json
  → verified-cves-upstream.json
                       ↓
verify-cves-in-source          ← this skill
  → verified-cves-source.json
                       ↓
compare-cve-results.py --source
  → comparison.json (unknowns resolved)
```
