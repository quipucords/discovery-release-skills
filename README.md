# Discovery Release Skills

Claude Code skills for managing the upstream quipucords and downstream Red Hat
Discovery release process. Currently, the skills focus on CVE tracking and
verification: querying CVE data from multiple sources (Red Hat Catalog, Prograde
advisory emails, JIRA, and the Errata API), merging the results into a unified
report, and verifying which CVEs are present or already fixed in a specific
container build. Future skills may cover broader release automation including
dependency updates, PR management, and upstream/downstream release coordination.

Skills are located in `.claude/skills/` and are auto-discovered by Claude Code.
Once you've completed [Prerequisites](#prerequisites) and [Setup](#setup),
see [Quick Start](#quick-start) to run your first report.

---

## Prerequisites

### Claude Code and uv

- **Claude Code** — [install instructions](https://claude.ai/download)
- **`uv`** — Python package runner used by all scripts:
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```

### Kerberos ticket

The errata advisory lookup requires a valid Kerberos ticket. You must be on the
Red Hat internal network or connected via VPN:
```bash
kinit <username>@YOUR_KERBEROS_REALM
klist -s && echo "ticket valid" || echo "need to kinit"
```

### JIRA API token

The skill connects to `redhat.atlassian.net`. Create an API token at
[id.atlassian.com](https://id.atlassian.com/manage-profile/security/api-tokens)
and set it as an environment variable — see [Setup](#setup) below.

### Gmail OAuth credentials

OAuth credentials are required to read Gmail. On the first run, a browser window
opens for authorization. Place your credentials file at:
```
~/.config/gmail/credentials.json
```

To create credentials (one-time setup):
1. Go to [console.cloud.google.com](https://console.cloud.google.com/) and create or select a project.
2. Enable the **Gmail API** for that project (APIs & Services → Library).
3. Create an OAuth 2.0 credential: APIs & Services → Credentials → Create Credentials → **OAuth client ID** → Application type: **Desktop app**.
4. Download the JSON file and save it as `~/.config/gmail/credentials.json`.

See the [Gmail API Quickstart](https://developers.google.com/gmail/api/quickstart/python)
for full instructions. If you don't receive Prograde advisory emails,
see [Team collaboration](#team-collaboration-sharing-prograde-data) below.

> **Non-default credential paths:** Set `GMAIL_CREDENTIALS_PATH` and/or `GMAIL_TOKEN_PATH`
> in `.claude/settings.local.json` if you store credentials outside the default locations
> — see [Setup](#setup) for details.

### GitHub CLI (`gh`) — optional but recommended

Used by `verify-cves-in-builds` and `verify-cves-in-source` to query the GitHub
Advisory Database for GHSA IDs and advisory metadata. Without it those lookups are
silently skipped and the affected CVEs will have less enrichment data in the report.

```bash
# macOS
brew install gh
gh auth login

# Fedora / RHEL
sudo dnf install -y gh
gh auth login
```

### podman

Used to pull and inspect container images:

```bash
# macOS
brew install podman
podman machine init && podman machine start
```

> **macOS note:** The podman machine does not start automatically after a
> reboot. Run `podman machine start` at the beginning of each session, or
> configure it to start on login with `podman machine start --no-info` in your
> shell profile.

```bash
# Fedora / RHEL
sudo dnf install -y podman
```

Downstream images (`registry.redhat.io`) require authentication:
```bash
podman login registry.redhat.io   # Red Hat Customer Portal credentials
```

Upstream images (`quay.io/quipucords`) are public — no login required. In
upstream-only mode the login check is skipped automatically.

---

## Setup

### 1. Set environment variables

Add these to `.claude/settings.local.json` inside this project directory. This file
is already gitignored, so credentials stay scoped to this project and never leak
into `~/.claude/settings.json` where they would be visible to every other Claude
Code project on your machine.

```json
{
  "env": {
    "JIRA_EMAIL": "you@redhat.com",
    "JIRA_API_TOKEN": "your-api-token",
    "ERRATA_HOST": "your-errata-host.example.com"
  }
}
```

| Variable | Default | Description |
|----------|---------|-------------|
| `JIRA_EMAIL` | *(required)* | Your Atlassian account email address. |
| `JIRA_API_TOKEN` | *(required)* | API token for `redhat.atlassian.net`. Tokens with insufficient scopes silently return 0 results — use one with full read permissions. |
| `ERRATA_HOST` | *(required)* | Hostname of your Errata Tool instance — **no `https://` prefix**, no trailing slash (e.g. `errata.example.com`). Ask a teammate if unsure. |
| `PROGRADE_LABEL` | `alerts/prograde` | Gmail label used to filter Prograde advisory emails. Override if your organization uses a different label. |
| `GMAIL_CREDENTIALS_PATH` | `~/.config/gmail/credentials.json` | Path to your Gmail OAuth credentials file. Override if you store it elsewhere. |
| `GMAIL_TOKEN_PATH` | `~/.config/gmail/token.json` | Path where the OAuth token cache is written. Override to keep it in a non-default location. |
| `JIRA_HOST` | `redhat.atlassian.net` | JIRA instance hostname. Override if your organization uses a different Atlassian tenant. |
| `PROGRADE_SENDER` | — | Sender address of Prograde advisory emails. Not used by the pipeline; useful for ad-hoc Gmail queries (e.g. `query-gmail.py --from "$PROGRADE_SENDER"`). Ask a teammate for the address. |

#### Source repo configuration (optional — used by `/verify-cves-in-source`)

These variables tell `verify-cves-in-source` where to find the quipucords and
quipucords-ui source repositories. If the repos are not present at the configured
paths, the skill clones them automatically using the URL variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `QUIPUCORDS_SERVER_REPO_PATH` | `../quipucords` | Local path to the quipucords server repo |
| `QUIPUCORDS_UI_REPO_PATH` | `../quipucords-ui` | Local path to the quipucords-ui repo |
| `QUIPUCORDS_SERVER_REPO_URL` | `git@github.com:quipucords/quipucords.git` | Clone URL used when the path does not exist |
| `QUIPUCORDS_UI_REPO_URL` | `git@github.com:quipucords/quipucords-ui.git` | Clone URL used when the path does not exist |

> **git and SSH key required for source check:** `git` must be in PATH, and an SSH
> key authorised for GitHub must be available if the repos need to be cloned. If the
> repos are already checked out at the default paths (`../quipucords` and
> `../quipucords-ui`), no SSH key is needed — the skill will fetch and check out the
> requested commitish in place.

### 2. Add permission allowlist (eliminates approval prompts)

In the happy path — running skills from the project root directory — Claude Code
should not prompt for approval on any command. Add a `permissions` block to
`.claude/settings.local.json` (the same file as your env vars from step 1):

```json
{
  "env": {
    "JIRA_EMAIL": "you@redhat.com",
    "JIRA_API_TOKEN": "your-api-token",
    "ERRATA_HOST": "your-errata-host.example.com"
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

## Quick Start

The fastest way to get a complete CVE status report is:

```
/run-cve-check-pipeline
```

This runs the full pipeline end-to-end — querying all configured sources (Red Hat
Catalog, Prograde emails, JIRA, and Errata), verifying which CVEs are fixed or
still present in the container builds, and writing a visual HTML report to
`cve-data/cve-report.html`. Open it with `open cve-data/cve-report.html` on
macOS or `xdg-open cve-data/cve-report.html` on Linux.

If you want to skip the interactive questions and accept all defaults (Prograde
since last release, compare downstream vs. upstream, all `latest` tags, source
check against `main`), append `default`:

```
/run-cve-check-pipeline default
```

---

## Team collaboration: sharing Prograde data

Prograde CVE advisory emails are only delivered to a subset of team members. If
you don't receive them, you can still get a complete CVE report — you just need a
teammate to export the raw email data and share it with you.

> **Prerequisites for the recipient:** You still need a valid Kerberos ticket
> (see [Prerequisites](#prerequisites)) and JIRA credentials (see [Setup](#setup))
> to run the full pipeline. Only the Gmail step is handled by the shared file.

### Step 1 — Teammate exports the file

The teammate who receives Prograde emails runs the Gmail query step directly:

```bash
uv run .claude/skills/query-gmail/scripts/query-gmail.py \
  --label "$PROGRADE_LABEL" \
  --since 2025-01-01 \
  > cve-data/prograde-emails.json
```

Replace `2025-01-01` with the date you want to query from (typically the date of
the last downstream Discovery release). The output is a plain JSON file with no
secrets or credentials — it is safe to share over Slack or email.

### Step 2 — You receive the file

Place the file your teammate sent you at `cve-data/prograde-emails.json` inside
this project directory. Create `cve-data/` first if it doesn't exist:

```bash
mkdir -p cve-data
# then copy or move the file here
```

### Step 3 — Run the pipeline using the provided file

When prompted by `/run-cve-check-pipeline`, choose:

> **No — use provided json file**

The pipeline will skip the Gmail query and read `cve-data/prograde-emails.json`
directly. All subsequent steps (parsing, errata lookups, merging) run normally,
so the resulting report is just as complete as if you had Gmail access.

> **Note:** If you accidentally select "No — skip Prograde" instead, the
> pipeline will overwrite your file with an empty stub. Re-copy the file from
> your teammate before running again.

---

## Skills

### Pipeline skills (invoke these directly)

| Skill | What it does |
|-------|-------------|
| `/run-cve-check-pipeline` | **One-stop shop.** Collects CVE data from all sources, then verifies builds. In compare mode, also offers an optional source lockfile check for non-RPM packages. Supports the same three modes as `/verify-cves-in-builds` below. |
| `/query-all-cves` | Data collection only. Queries all sources and produces `cve-data/unified-cves.json`. Use this if you don't need build verification. |
| `/verify-cves-in-builds` | Build verification only. Pulls container images and checks which CVEs from an existing `unified-cves.json` are present or fixed. Three modes: **downstream only** (check the released Discovery images), **upstream only** (check quipucords before cutting a release), or **compare** (delta report across both). Requires `unified-cves.json` from a prior `query-all-cves` run. |
| `/verify-cves-in-source` | Source code check for non-RPM packages. After `verify-cves-in-builds` (compare mode), reads `lockfiles/requirements.txt` and `lockfiles/requirements-build.txt` (pip) plus `package-lock.json` (npm) from the quipucords and quipucords-ui repos to resolve CVEs that RPM scanning left as **unknown**. Promotes resolved unknowns to `fixed_upstream_not_downstream` in the comparison report. |

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

## Output files

Most output is written to `cve-data/` (gitignored), with one exception:
`cve-data/package-types.json` is **not** gitignored — it is meant to be committed
so ecosystem annotations persist across runs and team members.

| File | Mode | Contents |
|------|------|----------|
| `cve-data/unified-cves.json` | all | All reported CVEs with severity, advisory links, and fix data |
| `cve-data/verified-cves-downstream.json` | downstream / compare | Per-container verification for downstream images |
| `cve-data/verified-cves-upstream.json` | upstream / compare | Per-container verification for upstream images |
| `cve-data/verified-cves-source.json` | compare + source check | Lockfile check results for non-RPM packages (npm/pip) |
| `cve-data/comparison.json` | compare | Delta between downstream and upstream per CVE |
| `cve-data/cve-report.html` | all | Visual HTML report |
| `cve-data/package-types.json` | all | Ecosystem annotations (`npm`, `pip`, etc.) for packages the pipeline couldn't auto-classify. Committed to the repo. |

The HTML report is filterable and sortable, supports light and dark mode, and
prominently calls out CVEs by priority: upstream regressions first, then unfixed
CVEs, then upstream fixes that are pending a downstream release. CVEs resolved via
source lockfile check are annotated with **[src]** in the upstream status column.

---

## Adapting for other products

The pipeline ships with defaults for the Discovery product. If you are adapting it
for a different product, set these additional environment variables in
`.claude/settings.local.json`. Discovery team members can ignore this section
entirely.

| Variable | Default | Description |
|----------|---------|-------------|
| `JIRA_PROJECT` | `DISCOVERY` | JIRA project key to search for CVE tracking issues |
| `JIRA_NVR_PATTERN` | Discovery regex | Full regex (with one capture group) matching NVR strings in JIRA issue summaries |
| `CATALOG_SERVER_NAME` | `discovery-server` | Short name for the server container in Red Hat Catalog queries |
| `CATALOG_UI_NAME` | `discovery-ui` | Short name for the UI container in Red Hat Catalog queries |
| `CATALOG_SERVER_ID` | Discovery hex ID | Red Hat Catalog repository ID for the server container (from the catalog page URL) |
| `CATALOG_UI_ID` | Discovery hex ID | Red Hat Catalog repository ID for the UI container |
| `DOWNSTREAM_SERVER_IMAGE` | `registry.redhat.io/discovery/discovery-server-rhel9` | Full base URL for the downstream server image |
| `DOWNSTREAM_UI_IMAGE` | `registry.redhat.io/discovery/discovery-ui-rhel9` | Full base URL for the downstream UI image |
| `UPSTREAM_SERVER_IMAGE` | `quay.io/quipucords/quipucords` | Full base URL for the upstream server image |
| `UPSTREAM_UI_IMAGE` | `quay.io/quipucords/quipucords-ui` | Full base URL for the upstream UI image |
| `PRODUCT_NAME` | `Discovery` | Human-readable downstream product name (used in reports) |
| `UPSTREAM_PRODUCT_NAME` | `quipucords` | Human-readable upstream project name (used in reports) |

> **Note on the two-container model:** The pipeline is built around exactly two
> containers (server + UI). Teams with a different number of containers would need
> to adapt the skill structure — this is a known limitation for v1.

---

## Development

### Running the tests

The test suite covers the core Python logic — RPM version comparison, CVE data
merging, delta classification, and source package checks. No credentials, network
access, or container images are required to run the tests.

```bash
# Run all tests (network-isolated)
uv run --with pytest --with pytest-socket pytest tests/

# Run a single test file
uv run --with pytest --with pytest-socket pytest tests/test_rpm_check.py -v
```

`pytest-socket` blocks all real socket connections during the test run. Any test
that accidentally attempts a live network call will fail immediately rather than
silently hanging or returning stale data. Subprocess-based calls (e.g. `gh api`)
are not intercepted at the socket level; those are guarded by pre-populating the
relevant in-memory caches via `monkeypatch` in the individual tests.

| Test file | What it covers |
|-----------|---------------|
| `test_rpm_check.py` | RPM NVRA parsing, `rpmvercmp` algorithm, `evr_gte` version comparison, module stream NVR detection, `check_cve_in_container` |
| `test_merge_cve_data.py` | CVE registry merging, errata indexing, fixed-package extraction, catalog/prograde/JIRA source processing |
| `test_compare_delta.py` | `container_delta` and `cve_delta` classification logic |
| `test_source_packages.py` | Source lockfile version comparison, GHSA/OSV parsing, source-aware delta logic |
| `test_rpm_python_expansion.py` | `_expand_python_names` — mapping `python-X` SRPMs to binary RPM variants |

### Adding tests

Tests live in `tests/` alongside the scripts they cover. Each test file loads its
target script via `importlib` so the scripts themselves need no special packaging.
Follow the pattern in any existing test file for the `_load()` helper.
