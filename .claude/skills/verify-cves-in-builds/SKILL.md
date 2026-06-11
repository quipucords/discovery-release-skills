---
name: verify-cves-in-builds
description: >
  Pull discovery-server and discovery-ui container images and verify which CVEs from
  cve-data/unified-cves.json are still present in those builds. Produces
  cve-data/verified-cves.json with per-container findings: was the vulnerable package
  found, what version is installed, and is that version new enough to be fixed?
  Run after query-all-cves.
compatibility: >
  podman must be installed and in PATH. cve-data/unified-cves.json must exist
  (run query-all-cves first). Network access to quay.io (or whichever registry
  hosts the target images) required. No authentication needed for public Quay.io
  images; run podman login first for private registries.
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
- Network access to the container registry (quay.io for default upstream images)

## Orchestration

### Step 0 — Gather options from the user

Before running anything, ask the user which container images to check.

**Default images (upstream Quay.io pre-publication builds):**
- Server: `quay.io/quipucords/quipucords:latest`
- UI:     `quay.io/quipucords/quipucords-ui:latest`

Ask whether these defaults are correct, or if the user wants to check a specific
tag (e.g. `:2.5.1`, a PR build digest, or a downstream `registry.redhat.io` image).
Each container's image can be specified independently.

### Step 0 — Navigate to project root

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
```

### Step 1 — Pull images and query installed RPMs (parallel)

Both images are pulled and queried in parallel internally — no shell background
jobs needed:

```bash
python3 .claude/skills/verify-cves-in-builds/scripts/pull-and-query-rpms.py \
  --server-image quay.io/quipucords/quipucords:latest \
  --ui-image quay.io/quipucords/quipucords-ui:latest
```

Outputs:
- `cve-data/rpms-server.txt` — full `rpm -qa` list from server image
- `cve-data/rpms-ui.txt` — full `rpm -qa` list from UI image
- `cve-data/checked-images.json` — maps container names to image URLs checked

### Step 2 — Compare installed RPMs against CVE fix data

```bash
python3 .claude/skills/verify-cves-in-builds/scripts/check-cves-in-rpms.py
```

Reads `unified-cves.json` and the RPM lists; writes `cve-data/verified-cves.json`.

### Step 3 — Print summary

```bash
python3 .claude/skills/verify-cves-in-builds/scripts/print-verification-summary.py
```

## Output: `cve-data/verified-cves.json`

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
  cve-data/verified-cves.json

# Count by fix status for each container
jq '.verification_summary' cve-data/verified-cves.json

# CVEs where fix is unknown (package not found or no fix NVR available)
jq '.cves[] | select(.checked_containers | to_entries[] | .value.is_fixed == null)
  | .cve_id' cve-data/verified-cves.json
```

## Pipeline

```
query-all-cves → cve-data/unified-cves.json
                         ↓
verify-cves-in-builds → cve-data/verified-cves.json
```
