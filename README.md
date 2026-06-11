# Discovery CVE Skills

Claude Code skills for tracking and verifying CVEs in the Red Hat Discovery
container images (`discovery-server-rhel9` and `discovery-ui-rhel9`). These
skills query CVE data from multiple sources (Red Hat Catalog, Prograde advisory
emails, JIRA, and the Errata API), merge the results into a unified report, and
optionally verify which CVEs are present or already fixed in a specific container
build.

Skills are located in `.claude/skills/` and are auto-discovered by Claude Code.

---

## Quick Start

The fastest way to get a complete CVE status report is:

```
/run-cve-check-pipeline
```

This single command runs the full pipeline end-to-end — collecting CVE data from
all configured sources, verifying which CVEs are fixed or still present in the
container builds, and producing both a machine-readable JSON report and a visual
HTML report you can open in a browser.

Before running it for the first time, complete the [Prerequisites](#prerequisites)
and [Setup](#setup) sections below.

---

## Skills

### Pipeline skills (invoke these directly)

| Skill | What it does |
|-------|-------------|
| `/run-cve-check-pipeline` | **One-stop shop.** Collects CVE data from all sources, then verifies which CVEs are present/fixed in actual container builds. Produces `cve-data/unified-cves.json`, `cve-data/verified-cves.json`, and `cve-data/cve-report.html`. |
| `/query-all-cves` | Data collection only. Queries all sources and produces `cve-data/unified-cves.json`. Use this if you don't need build verification. |
| `/verify-cves-in-builds` | Build verification only. Pulls container images and checks which CVEs from an existing `unified-cves.json` are present or fixed. Requires `unified-cves.json` from a prior `query-all-cves` run. |

### Data source skills (called automatically by the pipeline)

| Skill | Source |
|-------|--------|
| `/query-gmail` | Prograde CVE advisory notification emails via Gmail |
| `/parse-prograde-advisories` | Parses Prograde email HTML into structured advisory data |
| `/query-redhat-catalog` | CVEs in the published downstream Discovery images |
| `/query-jira-cves` | Internally tracked CVEs in the DISCOVERY JIRA project |
| `/query-errata-advisory` | CVE IDs and fixed package NVRs for a given advisory |
| `/merge-cve-data` | Merges data from any combination of the above sources |

You rarely need to invoke the data source skills directly — the pipeline skills
handle orchestration.

---

## Prerequisites

### Required for all skills
- **Claude Code** — [install instructions](https://claude.ai/download)
- **`uv`** — Python package runner used by all scripts:
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```

### Required for `/query-all-cves` and `/run-cve-check-pipeline`

**Red Hat Errata API (Kerberos)**
The errata advisory lookup requires a valid Kerberos ticket from the Red Hat
internal network:
```bash
kinit <username>@YOUR_KERBEROS_REALM
klist -s && echo "ticket valid" || echo "need to kinit"
```

**JIRA API token** *(if querying JIRA)*
Create a token at [id.atlassian.com](https://id.atlassian.com/manage-profile/security/api-tokens).
Set as environment variables — see [Setup](#setup) below.

> **Note on JIRA token scopes:** Use an API token with sufficient read permissions.
> Tokens with insufficient scopes silently return 0 results rather than an error,
> making it look like there are no open CVE issues.

**Gmail OAuth credentials** *(if querying Prograde emails)*
OAuth credentials are required to read Gmail. On the first run, a browser window
opens for authorization. Place your credentials file at:
```
~/.config/gmail/credentials.json
```
See the [Gmail API Quickstart](https://developers.google.com/gmail/api/quickstart/python)
for how to obtain credentials. If you don't receive Prograde advisory emails,
you can skip the Gmail step when prompted by the pipeline skill.

### Required for `/verify-cves-in-builds` and `/run-cve-check-pipeline`

**podman** — used to pull and inspect container images:
```bash
# macOS
brew install podman
podman machine init && podman machine start
```

**Downstream images only:** `registry.redhat.io` requires authentication:
```bash
podman login registry.redhat.io   # Red Hat Customer Portal credentials
```
Public Quay.io images (the default) do not require login.

---

## Setup

### 1. Set JIRA credentials

Add your JIRA credentials to `~/.claude/settings.json` so they are available in
every Claude Code session. This file is never committed to any repository.

```json
{
  "env": {
    "JIRA_EMAIL": "you@redhat.com",
    "JIRA_API_TOKEN": "your-api-token"
  }
}
```

Alternatively, set them in `.claude/settings.local.json` (project-local, gitignored)
if you prefer to keep them scoped to this project.

### 2. Add permission allowlist (eliminates approval prompts)

In the happy path — running skills from the project root directory — Claude Code
should not prompt for approval on any command. Add this `permissions` block to
your `~/.claude/settings.json` or `.claude/settings.local.json`:

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

These two patterns cover all commands Claude runs directly. All other commands
(`klist`, `podman`, `mkdir`, etc.) are called internally by the Python scripts
via `subprocess` and do not need allowlist entries.

> **Important:** Always invoke skills from the project root directory (the directory
> containing `.claude/`). The skills verify this and will exit with a clear error
> if you are in the wrong directory.

---

## Output files

All output is written to `cve-data/` (gitignored):

| File | Contents |
|------|----------|
| `cve-data/unified-cves.json` | All reported CVEs with severity, advisory links, and fix data |
| `cve-data/verified-cves.json` | Per-container verification: fixed / not fixed / UNKNOWN / not found |
| `cve-data/cve-report.html` | Visual HTML report — open with `open cve-data/cve-report.html` |

The HTML report is filterable and sortable, supports light and dark mode, and
prominently calls out any CVEs that require manual investigation.
