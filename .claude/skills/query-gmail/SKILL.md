---
name: query-gmail
description: >
  Query Gmail for email messages matching filters (label, sender, recipient, subject
  regex, date). Use when you need to retrieve Prograde CVE advisory notification emails
  or any other labeled Gmail messages as the first step in the CVE tracking pipeline.
compatibility: >
  Gmail API OAuth2 credentials required. On first run, a browser window opens for
  authorization. Credentials stored at ~/.config/gmail/credentials.json (override with
  GMAIL_CREDENTIALS_PATH). Token cached at ~/.config/gmail/token.json (override with
  GMAIL_TOKEN_PATH). uv required.
metadata:
  topic: cve-tracking
---

## When to use

Use this skill at the **start of the CVE pipeline** to fetch Prograde security advisory
notification emails from Gmail. Prograde emails are the earliest source of new RHSA
advisories — often available before CVEs appear in JIRA or the Red Hat Catalog.

Also useful for any ad-hoc Gmail query during release preparation.

## Prerequisites

1. Gmail OAuth credentials at `~/.config/gmail/credentials.json`
   (see the project SETUP.md for one-time setup instructions)
2. `uv` installed

## Invocation

```bash
mkdir -p cve-data

# Fetch Prograde emails since a given date and save for downstream processing
uv run .claude/skills/query-gmail/scripts/query-gmail.py \
  --label "alerts/prograde" \
  --since "2026-05-01" \
  > cve-data/prograde-emails.json

# See all options
uv run .claude/skills/query-gmail/scripts/query-gmail.py --help
```

## Output

JSON to stdout: `{"messages": [{...}, ...]}` where each message contains:
`message_id`, `subject`, `from`, `to`, `cc`, `date`, `body`, `labels`.

All logs go to stderr. Only JSON goes to stdout — safe to pipe or redirect.

## Pipeline

```
query-gmail → parse-prograde-advisories → query-errata-advisory ─┐
                                                                   └→ merge-cve-data
query-redhat-catalog ──────────────────────────────────────────────┘
query-jira-cves ───────────────────────────────────────────────────┘
```

This skill is a data source. Pass its output to the `parse-prograde-advisories` skill
as the next step. The full pipeline is orchestrated by the `merge-cve-data` skill.
