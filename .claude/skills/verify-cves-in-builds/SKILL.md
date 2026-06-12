---
name: verify-cves-in-builds
description: >
  Pull Discovery container images and verify which CVEs from cve-data/unified-cves.json
  are still present. Supports single-set mode (downstream only) or dual-set comparison
  mode (downstream vs. upstream), producing a delta report that highlights backport
  candidates. Run after query-all-cves.
compatibility: >
  podman must be installed and in PATH. cve-data/unified-cves.json must exist
  (run query-all-cves first). registry.redhat.io authentication required for downstream
  images — run `podman login registry.redhat.io` first. Network access to quay.io
  required for upstream images (no auth needed).
metadata:
  topic: cve-tracking
---

## When to use

Use this skill after `query-all-cves` has produced `cve-data/unified-cves.json`.
It answers the question: *for a specific container build, are the vulnerable packages
still at a version affected by each CVE, or have they been updated?*

This is the second phase of CVE tracking — `query-all-cves` collects what CVEs
*should* be present based on published data; this skill checks what *is actually*
installed in a real build.

## Prerequisites

- `cve-data/unified-cves.json` must exist — run `query-all-cves` first
- `podman` installed and in PATH
- Network access to the container registry
- **Downstream images only:** `registry.redhat.io` requires authentication.
  Log in before running this skill:
  ```bash
  podman login registry.redhat.io
  ```
  Use your Red Hat Customer Portal credentials. See:
  https://access.redhat.com/RegistryAuthentication

  `pull-and-query-rpms.py` checks authentication automatically before
  attempting any pulls and exits with a clear error if not logged in.
  There is no need to add a separate auth check step before running it.

## Orchestration

### Step 1 — Gather options from the user

**Question 1: Mode selection**

```
AskUserQuestion({
  "questions": [{
    "question": "Which images do you want to check?",
    "header": "Mode",
    "multiSelect": false,
    "options": [
      {
        "label": "Compare downstream vs. upstream",
        "description": "Check both registries and produce a delta report: regressions, unfixed CVEs, and which upstream fixes are pending a downstream release."
      },
      {
        "label": "Downstream only",
        "description": "Check registry.redhat.io/discovery images. Use to verify the current downstream release."
      },
      {
        "label": "Upstream only",
        "description": "Check quay.io/quipucords images. Use to verify the upstream quipucords build before cutting a release."
      }
    ]
  }]
})
```

**Question 2a: If Downstream only — ask two tag questions**

```
AskUserQuestion({
  "questions": [
    {
      "question": "What tag for the downstream discovery-server image?",
      "header": "Server tag ↓",
      "multiSelect": false,
      "options": [
        {"label": "latest", "description": "registry.redhat.io/discovery/discovery-server-rhel9:latest"},
        {"label": "Custom", "description": "Type a specific tag (e.g. 2.5) in the Other field"}
      ]
    },
    {
      "question": "What tag for the downstream discovery-ui image?",
      "header": "UI tag ↓",
      "multiSelect": false,
      "options": [
        {"label": "latest", "description": "registry.redhat.io/discovery/discovery-ui-rhel9:latest"},
        {"label": "Custom", "description": "Type a specific tag (e.g. 2.6) in the Other field"}
      ]
    }
  ]
})
```

**Question 2b: If Upstream only — ask two tag questions**

```
AskUserQuestion({
  "questions": [
    {
      "question": "What tag for the upstream discovery-server image?",
      "header": "Server tag ↑",
      "multiSelect": false,
      "options": [
        {"label": "latest", "description": "quay.io/quipucords/quipucords:latest"},
        {"label": "Custom", "description": "Type a specific tag in the Other field"}
      ]
    },
    {
      "question": "What tag for the upstream discovery-ui image?",
      "header": "UI tag ↑",
      "multiSelect": false,
      "options": [
        {"label": "latest", "description": "quay.io/quipucords/quipucords-ui:latest"},
        {"label": "Custom", "description": "Type a specific tag in the Other field"}
      ]
    }
  ]
})
```

**Question 2c: If Compare — ask four tag questions**

```
AskUserQuestion({
  "questions": [
    {
      "question": "What tag for downstream discovery-server (registry.redhat.io)?",
      "header": "DS Server tag",
      "multiSelect": false,
      "options": [
        {"label": "latest", "description": "registry.redhat.io/discovery/discovery-server-rhel9:latest"},
        {"label": "Custom", "description": "Type a specific tag in the Other field"}
      ]
    },
    {
      "question": "What tag for downstream discovery-ui (registry.redhat.io)?",
      "header": "DS UI tag",
      "multiSelect": false,
      "options": [
        {"label": "latest", "description": "registry.redhat.io/discovery/discovery-ui-rhel9:latest"},
        {"label": "Custom", "description": "Type a specific tag in the Other field"}
      ]
    },
    {
      "question": "What tag for upstream discovery-server (quay.io/quipucords)?",
      "header": "US Server tag",
      "multiSelect": false,
      "options": [
        {"label": "latest", "description": "quay.io/quipucords/quipucords:latest"},
        {"label": "Custom", "description": "Type a specific tag in the Other field"}
      ]
    },
    {
      "question": "What tag for upstream discovery-ui (quay.io/quipucords)?",
      "header": "US UI tag",
      "multiSelect": false,
      "options": [
        {"label": "latest", "description": "quay.io/quipucords/quipucords-ui:latest"},
        {"label": "Custom", "description": "Type a specific tag in the Other field"}
      ]
    }
  ]
})
```

If the user selects "Custom" for any tag, use the value they type via "Other" as the tag.

### Step 2 — Navigate to project root

```bash
python3 .claude/skills/check-location.py
```

> **Always use relative paths** when invoking scripts in this skill — never
> absolute paths. The allowlist that permits these commands matches the
> relative form `python3 .claude/skills/...` only.

### Step 3 — Pull images and query RPMs

**Downstream only:**
```bash
python3 .claude/skills/verify-cves-in-builds/scripts/pull-and-query-rpms.py --downstream-server-tag DS_SERVER_TAG --downstream-ui-tag DS_UI_TAG
```

**Upstream only:**
```bash
python3 .claude/skills/verify-cves-in-builds/scripts/pull-and-query-rpms.py --upstream-server-tag US_SERVER_TAG --upstream-ui-tag US_UI_TAG
```

**Compare mode:**
```bash
python3 .claude/skills/verify-cves-in-builds/scripts/pull-and-query-rpms.py --downstream-server-tag DS_SERVER_TAG --downstream-ui-tag DS_UI_TAG --upstream-server-tag US_SERVER_TAG --upstream-ui-tag US_UI_TAG
```

Substitute the tag values from Step 1 answers. Multiple images are pulled in parallel internally. No `registry.redhat.io` authentication is needed for upstream-only mode (quay.io is public).

### Step 4 — Verify CVEs against installed RPMs

**Downstream only:**
```bash
python3 .claude/skills/verify-cves-in-builds/scripts/check-cves-in-rpms.py --set downstream
```

**Upstream only:**
```bash
python3 .claude/skills/verify-cves-in-builds/scripts/check-cves-in-rpms.py --set upstream
```

**Compare mode (run both sequentially):**
```bash
python3 .claude/skills/verify-cves-in-builds/scripts/check-cves-in-rpms.py --set downstream
python3 .claude/skills/verify-cves-in-builds/scripts/check-cves-in-rpms.py --set upstream
```

### Step 5 — Compare results (comparison mode only)

```bash
python3 .claude/skills/verify-cves-in-builds/scripts/compare-cve-results.py
```

Skip this step in downstream-only and upstream-only modes.

### Step 6 — Print summary

**Downstream only:**
```bash
python3 .claude/skills/verify-cves-in-builds/scripts/print-verification-summary.py
```

**Upstream only:**
```bash
python3 .claude/skills/verify-cves-in-builds/scripts/print-verification-summary.py --set upstream
```

**Compare mode:**
```bash
python3 .claude/skills/verify-cves-in-builds/scripts/print-verification-summary.py --comparison
```

**IMPORTANT:** Present the complete output of this script to the user verbatim.
Do NOT reformat, summarize, or omit any section of it. In particular, any section
marked `*** ACTION REQUIRED ***` contains items the user must manually verify —
these MUST appear in your response exactly as printed, word for word.

### Step 7 — Generate HTML report

**Downstream only:**
```bash
python3 .claude/skills/verify-cves-in-builds/scripts/generate-html-report.py
```

**Upstream only:**
```bash
python3 .claude/skills/verify-cves-in-builds/scripts/generate-html-report.py --set upstream
```

**Compare mode:**
```bash
python3 .claude/skills/verify-cves-in-builds/scripts/generate-html-report.py --comparison
```

After this runs, explicitly tell the user:

> A visual HTML report has been written to `cve-data/cve-report.html`.
> Open it in a browser:
> - macOS: `open cve-data/cve-report.html`
> - Linux: `xdg-open cve-data/cve-report.html`
>
> In comparison mode it shows a unified table with downstream and upstream
> status columns side by side, a Delta column (e.g. "Backport needed"), and
> an ACTION REQUIRED section listing CVEs that need attention.

## Output: `cve-data/verified-cves-downstream.json` (single-set) / `cve-data/comparison.json` (comparison)

Same structure as `unified-cves.json` with two additions:

**Top-level `verification` block:**
```json
{
  "verified_at": "2026-06-11T14:32:00Z",
  "verification": {
    "images": {
      "discovery/discovery-server-rhel9": "quay.io/quipucords/quipucords:latest",
      "discovery/discovery-ui-rhel9": "quay.io/quipucords/quipucords-ui:latest"
    }
  }
}
```

**Per-CVE `checked_containers` map** (alongside `affected_containers`):
```json
{
  "cve_id": "CVE-2026-12345",
  "affected_containers": ["discovery/discovery-server-rhel9"],
  "checked_containers": {
    "discovery/discovery-server-rhel9": {
      "checked_image": "quay.io/quipucords/quipucords:latest",
      "package_found": true,
      "installed_nvras": ["nginx-1.24.0-5.el9.x86_64"],
      "minimum_fixed_nvr": "nginx-1.24.0-6.el9",
      "is_fixed": false
    }
  }
}
```

**`is_fixed` values:**
- `true` — installed version meets or exceeds the minimum fixed NVR
- `false` — installed version is older than the minimum fixed NVR (CVE still present)
- `null` — package not found in the container, or fixed version is unknown

## Useful jq queries

```bash
# List all unfixed CVEs in the server build
jq '.cves[] | select(.checked_containers["discovery/discovery-server-rhel9"].is_fixed == false)
  | {cve_id, severity, installed: .checked_containers["discovery/discovery-server-rhel9"].installed_nvras,
     needs: .checked_containers["discovery/discovery-server-rhel9"].minimum_fixed_nvr}' \
  cve-data/verified-cves-downstream.json

# Count by fix status for each container
jq '.verification_summary' cve-data/verified-cves-downstream.json

# CVEs where fix is unknown (package not found or no fix NVR available)
jq '.cves[] | select(.checked_containers | to_entries[] | .value.is_fixed == null)
  | .cve_id' cve-data/verified-cves-downstream.json
```

## Pipeline

```
query-all-cves → cve-data/unified-cves.json
                         ↓
verify-cves-in-builds → cve-data/verified-cves-downstream.json (or comparison.json in compare mode)
```
