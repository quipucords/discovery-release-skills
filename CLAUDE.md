# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run tests (network-isolated)
uv run --with pytest --with pytest-socket pytest tests/

# Run a single test file
uv run --with pytest --with pytest-socket pytest tests/test_compare_delta.py

# Invoke a skill script directly (always use relative paths from project root)
python3 .claude/skills/<skill-name>/scripts/<script>.py [args]

# Export Prograde emails for sharing with teammates
uv run .claude/skills/query-gmail/scripts/query-gmail.py --label "$PROGRADE_LABEL" --since YYYY-MM-DD > cve-data/prograde-emails.json
```

**Important:** Always invoke scripts with relative paths (`python3 .claude/skills/...`). The permissions allowlist matches the relative form only — absolute paths will trigger an approval prompt.

All scripts must be run from the project root directory. `check-location.py` enforces this and creates `cve-data/` if missing.

## Architecture

This project is a collection of Claude Code skills for CVE tracking in the Discovery (quipucords) release process. Skills live in `.claude/skills/` and are auto-discovered by Claude Code.

### Skill structure

Each skill has:
- `SKILL.md` — orchestration instructions Claude follows when the skill is invoked
- `scripts/` — Python scripts that do the actual work (called via `python3 .claude/skills/...`)

Claude Code reads the SKILL.md and calls the scripts in sequence; the scripts are not called directly by users.

### CVE pipeline (two phases)

**Phase 1 — Data collection (`query-all-cves`)**

Queries three sources in parallel, then enriches with errata data:

```
query-gmail ──→ parse-prograde-advisories ──┐
                                            ├──→ query-errata-advisory (per advisory) ──┐
query-redhat-catalog ───────────────────────┘                                           ├──→ merge-cve-data
query-jira-cves ────────────────────────────────────────────────────────────────────────┘
         ↓
  cve-data/unified-cves.json
```

**Phase 2 — Build verification (`verify-cves-in-builds`)**

Pulls container images with podman, queries installed RPMs, and compares them against the minimum fixed NVRs from errata. Supports three modes: downstream only, upstream only, or compare (delta report). For CVEs with no errata NVR, falls back to GitHub Advisory → OSV → NVD to find a fix version.

```
cve-data/unified-cves.json
         ↓
pull-and-query-rpms.py → check-cves-in-rpms.py → compare-cve-results.py
         ↓
  cve-data/verified-cves-downstream.json (or comparison.json)
```

**Phase 2.5 — Source check (`verify-cves-in-source`, optional)**

For CVEs that RPM scanning left as **unknown** (non-RPM packages such as npm or pip), checks upstream source lockfiles to determine fix status.

```
cve-data/verified-cves-downstream.json + verified-cves-upstream.json
         ↓
check-source-packages.py → compare-cve-results.py --source
         ↓
  cve-data/verified-cves-source.json
  cve-data/comparison.json (unknowns resolved)
  cve-data/cve-report.html
```

### Pipeline entry points

| Skill | Purpose |
|-------|---------|
| `run-cve-check-pipeline` | One-stop shop: runs both phases end-to-end, with optional source check |
| `query-all-cves` | Phase 1 only (data collection) |
| `verify-cves-in-builds` | Phase 2 only (requires existing `unified-cves.json`) |
| `verify-cves-in-source` | Phase 2.5 only: source lockfile check for non-RPM packages (requires both verified-cves files from compare mode) |

### Output files (`cve-data/`, gitignored)

| File | Contents |
|------|----------|
| `unified-cves.json` | All CVEs with severity, advisory links, fix data |
| `verified-cves-downstream.json` | Downstream container verification results |
| `verified-cves-upstream.json` | Upstream verification results |
| `verified-cves-source.json` | Source lockfile check results for non-RPM packages (npm/pip) |
| `comparison.json` | Per-CVE delta between downstream and upstream |
| `cve-report.html` | Filterable/sortable HTML report |
| `package-types.json` | Manual ecosystem annotations for UNKNOWN packages |
| `release-notes-cves.yaml` | CVE list for `spec.data.releaseNotes.cves` in a Konflux Release YAML |

### MCP servers

The skills use MCP tools for external integrations (not direct subprocess calls):
- `mcp__gmail__*` — Gmail OAuth for Prograde advisory emails
- `mcp__jira__*` — JIRA for internally tracked CVEs (DISCOVERY project)
- `mcp__errata-advisory__*` — Red Hat Errata API (requires Kerberos ticket)
- `mcp__red-hat-catalog__*` — Red Hat Container Catalog CVE data
- `mcp__cve-verifier__*` — RPM version comparison logic

### Tests

`tests/test_compare_delta.py` tests the delta classification logic in `verify-cves-in-builds/scripts/compare-cve-results.py`. It loads the module via `importlib` (no package structure). Add tests alongside new delta or comparison logic.

`tests/test_source_packages.py` tests the source lockfile reading, version comparison, package name normalization, and source-merge logic in `verify-cves-in-source/scripts/check-source-packages.py` and the `merge_source_into_upstream` / `source_aware_delta` functions in `compare-cve-results.py`.

`tests/test_rpm_python_expansion.py` tests the `_expand_python_names` function in `verify-cves-in-builds/scripts/check-cves-in-rpms.py`. It covers the expansion of `python-X` SRPM names to binary RPM variants (`python3-X`, `python3.12-X`) and the boundary between SRPM and wheel packages.

### Required environment variables

Set in `~/.claude/settings.json` or `.claude/settings.local.json`:

#### Authentication (required)

| Variable | Used by |
|----------|---------|
| `JIRA_EMAIL` | query-jira-cves |
| `JIRA_API_TOKEN` | query-jira-cves |
| `ERRATA_HOST` | query-errata-advisory |
| `BREW_HOST` | query-errata-advisory (optional, for Brew UI links) |
| `PROGRADE_SENDER` | query-gmail |
| `PROGRADE_LABEL` | query-gmail |

#### Product configuration (optional, have Discovery defaults)

| Variable | Default | Used by |
|----------|---------|---------|
| `JIRA_PROJECT` | `DISCOVERY` | query-jira-cves — project key to search |
| `JIRA_NVR_PATTERN` | Discovery-specific regex | query-jira-cves — regex to extract NVR from issue summary |
| `CATALOG_SERVER_NAME` | `discovery-server` | query-redhat-catalog, query-all-cves — short name for server |
| `CATALOG_UI_NAME` | `discovery-ui` | query-redhat-catalog, query-all-cves — short name for UI |
| `CATALOG_SERVER_ID` | Discovery catalog hex ID | query-redhat-catalog — Red Hat Catalog repo ID |
| `CATALOG_UI_ID` | Discovery catalog hex ID | query-redhat-catalog — Red Hat Catalog repo ID |
| `DOWNSTREAM_SERVER_IMAGE` | `registry.redhat.io/discovery/discovery-server-rhel9` | verify-cves-in-builds, merge-cve-data |
| `DOWNSTREAM_UI_IMAGE` | `registry.redhat.io/discovery/discovery-ui-rhel9` | verify-cves-in-builds, merge-cve-data |
| `UPSTREAM_SERVER_IMAGE` | `quay.io/quipucords/quipucords` | verify-cves-in-builds |
| `UPSTREAM_UI_IMAGE` | `quay.io/quipucords/quipucords-ui` | verify-cves-in-builds |
| `PRODUCT_NAME` | `Discovery` | generate-html-report, print-verification-summary |
| `UPSTREAM_PRODUCT_NAME` | `quipucords` | generate-html-report, print-verification-summary |

#### Source repo configuration (optional, used by verify-cves-in-source)

| Variable | Default | Used by |
|----------|---------|---------|
| `QUIPUCORDS_SERVER_REPO_PATH` | `../quipucords` | verify-cves-in-source — local path to quipucords repo |
| `QUIPUCORDS_UI_REPO_PATH` | `../quipucords-ui` | verify-cves-in-source — local path to quipucords-ui repo |
| `QUIPUCORDS_SERVER_REPO_URL` | `git@github.com:quipucords/quipucords.git` | verify-cves-in-source — clone URL if path is absent |
| `QUIPUCORDS_UI_REPO_URL` | `git@github.com:quipucords/quipucords-ui.git` | verify-cves-in-source — clone URL if path is absent |

> **Note:** The pipeline assumes exactly two containers (server + UI). Teams with a different number of containers would need to adapt the skill structure.
