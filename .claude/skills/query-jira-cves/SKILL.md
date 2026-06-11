---
name: query-jira-cves
description: >
  Search JIRA for CVE-related security issues in the DISCOVERY project. Use when you
  need internally tracked CVEs, including embargoed ones not yet visible in the Red Hat
  Catalog or Prograde emails, and their tracking status with due dates.
compatibility: >
  JIRA_EMAIL and JIRA_API_TOKEN environment variables required. Obtain an API token at
  https://id.atlassian.com/manage-profile/security/api-tokens. uv required.
metadata:
  topic: cve-tracking
---

## When to use

Use this skill to find CVEs that are being tracked internally in JIRA but may not yet
appear in public sources. JIRA issues may be created for:
- **Embargoed CVEs** (not yet public — only visible here)
- CVEs being tracked for resolution before a release
- CVEs with due dates set by the security team

Results include JIRA issue status and due date, which is useful for prioritizing which
CVEs need attention before an upcoming release.

## Prerequisites

`JIRA_EMAIL` and `JIRA_API_TOKEN` must be set in your environment. Set them via the
`env` block in `~/.claude/settings.json` or `.claude/settings.local.json` — see the
project README for details.

## Invocation

```bash
mkdir -p cve-data

# Search for open CVE issues (default: excludes Done/Closed, last 90 days)
uv run .claude/skills/query-jira-cves/scripts/query-jira-cves.py --summary-contains "CVE" > cve-data/jira.json

# Include closed issues (wider view)
uv run .claude/skills/query-jira-cves/scripts/query-jira-cves.py --summary-contains "CVE" --no-status-filter > cve-data/jira.json

# Extend the date window
uv run .claude/skills/query-jira-cves/scripts/query-jira-cves.py --summary-contains "CVE" --since 2025-12-01 > cve-data/jira.json

# See all options
uv run .claude/skills/query-jira-cves/scripts/query-jira-cves.py --help
```

## Output

JSON to stdout: `{"issues": [{...}, ...]}` where each issue contains:
`key`, `summary`, `description`, `status`, `labels`, `cve_ids`, `package_name`,
`vulnerable_package_nvrs` (VULNERABLE versions, not fixed), `upstream_fixed_versions`,
`downstream_component` (affected container), `duedate`, `linked_issues`, `url`.

**Important:** `vulnerable_package_nvrs` contains the **vulnerable** package version,
not the fixed version. Use `query-errata-advisory` to find fixed NVRs.

## Pipeline

This skill is a data source. Its output (`jira.json`) is consumed by the
`merge-cve-data` skill, which orchestrates the full pipeline. Invoke
`merge-cve-data` when you are ready to produce a unified CVE report.
