# Discovery CVE Skills

A set of [Claude Code skills](https://agentskills.io) for tracking CVEs in the Red Hat Discovery container images. Skills are located in `.claude/skills/` and are auto-discovered by Claude Code.

## Skills

| Skill | Purpose |
|-------|---------|
| `query-gmail` | Fetch Prograde CVE advisory notification emails |
| `parse-prograde-advisories` | Parse Prograde emails into structured advisory data |
| `query-redhat-catalog` | Get CVEs in the published downstream Discovery images |
| `query-jira-cves` | Find internally tracked CVEs in the DISCOVERY JIRA project |
| `query-errata-advisory` | Get CVE IDs and fixed package NVRs for a given advisory |
| `merge-cve-data` | Merge all sources into a single deduplicated report |

## Environment Variables

The `query-jira-cves` skill requires two environment variables:

| Variable | Description |
|----------|-------------|
| `JIRA_EMAIL` | Your Red Hat email address |
| `JIRA_API_TOKEN` | API token from [id.atlassian.com](https://id.atlassian.com/manage-profile/security/api-tokens) |

Claude Code injects variables from the `env` block in `settings.json` into every session, making them available to any script invoked by a skill. There are two good places to set them:

| Location | Scope | Committed to git? |
|----------|-------|-------------------|
| `~/.claude/settings.json` | All projects on your machine | No |
| `.claude/settings.local.json` | This project only | No — gitignored by convention |

Since these are personal credentials, **`~/.claude/settings.json`** is recommended — they follow you across projects and never risk ending up in the repo.

To set them in `.claude/settings.local.json` (project-local), add an `env` block alongside any existing content:

```json
{
  "env": {
    "JIRA_EMAIL": "you@redhat.com",
    "JIRA_API_TOKEN": "your-api-token"
  },
  "permissions": {
    "allow": []
  }
}
```

The same `env` block works identically in `~/.claude/settings.json`.

## Reducing Approval Prompts

By default, Claude Code prompts for approval before running shell commands. You can
pre-approve the predictable commands these skills use by adding them to the `allow`
list in `.claude/settings.local.json`:

```json
{
  "env": {
    "JIRA_EMAIL": "you@redhat.com",
    "JIRA_API_TOKEN": "your-api-token"
  },
  "permissions": {
    "allow": [
      "Bash(python3 .claude/skills/*)",
      "Bash(uv run .claude/skills/*)"
    ]
  }
}
```

These two entries cover virtually all commands Claude runs directly:

| Pattern | What it allows |
|---------|---------------|
| `python3 .claude/skills/*` | All `query-all-cves` helper scripts (the bulk of the pipeline) |
| `uv run .claude/skills/*` | Direct invocations of individual skill scripts |

Note: commands like `klist -s`, `mkdir -p cve-data`, and `uv run` are called
internally by the Python helper scripts via `subprocess` — not directly by Claude —
so they do not need allowlist entries.

**One prompt remains:** each skill's invocation section begins with a root-finding
bash block that contains conditional logic and `cd`. This compound statement cannot
be practically expressed as a single allowlist pattern, so it will still require a
one-time approval at the start of each skill run.
