#!/usr/bin/env python3
"""Generate a release-notes CVE YAML snippet for an upcoming downstream release.

Reads:  cve-data/comparison.json
Writes: cve-data/release-notes-cves.yaml

The release notes list CVEs that are fixed upstream but not yet in the current
downstream build — i.e. what the new downstream release will address. These are
the CVEs whose per-container delta is "fixed_upstream_not_downstream".

Each output entry has a `key` (CVE ID) and `component` (e.g. discovery-server
or discovery-ui). A CVE pending release for both containers produces two entries.

All progress goes to stderr. Exits non-zero on failure.
"""
import json
import os
import sys
from datetime import datetime, timezone

# Container key → component name mapping (mirrors check-cves-in-rpms.py).
SERVER_CONTAINER = os.environ.get(
    "DOWNSTREAM_SERVER_IMAGE",
    "registry.redhat.io/discovery/discovery-server-rhel9",
).split("/", 1)[1]
UI_CONTAINER = os.environ.get(
    "DOWNSTREAM_UI_IMAGE",
    "registry.redhat.io/discovery/discovery-ui-rhel9",
).split("/", 1)[1]

SERVER_COMPONENT = os.environ.get("CATALOG_SERVER_NAME", "discovery-server")
UI_COMPONENT     = os.environ.get("CATALOG_UI_NAME",     "discovery-ui")

CONTAINER_TO_COMPONENT = {
    SERVER_CONTAINER: SERVER_COMPONENT,
    UI_CONTAINER:     UI_COMPONENT,
}

_PRODUCT_NAME = os.environ.get("PRODUCT_NAME", "Discovery")

# ── Load comparison data ───────────────────────────────────────────────────────

cmp_path = "cve-data/comparison.json"

try:
    with open(cmp_path) as f:
        data = json.load(f)
except FileNotFoundError:
    print(f"Error: {cmp_path} not found. Run compare-cve-results.py first.",
          file=sys.stderr)
    sys.exit(1)
except json.JSONDecodeError as e:
    print(f"Error: invalid JSON in {cmp_path}: {e}", file=sys.stderr)
    sys.exit(1)

# ── Load source check data (optional) ────────────────────────────────────────
# verified-cves-source.json resolves non-RPM packages (npm, pip) that RPM
# scanning leaves as "unknown". When present, CVEs with delta "unknown" are
# re-evaluated: if the upstream source confirms is_fixed=true, the CVE is
# treated as fixed_upstream_not_downstream and included in the release notes.

src_index: dict = {}
src_path = "cve-data/verified-cves-source.json"
try:
    with open(src_path) as f:
        src_data = json.load(f)
    src_index = {c["cve_id"]: c for c in src_data.get("cves", [])}
    print(f"Loaded source check data for {len(src_index)} CVEs from {src_path}.",
          file=sys.stderr)
except FileNotFoundError:
    pass  # source check is optional
except json.JSONDecodeError as e:
    print(f"Warning: could not parse {src_path}: {e}; ignoring.", file=sys.stderr)

# ── Collect pending-release CVE/component pairs ───────────────────────────────

# Each entry: (cve_id, component_name)
# A CVE is included for a container when upstream has the fix but downstream
# does not yet — meaning it will be addressed by the new downstream release.
pending_pairs: list[tuple[str, str]] = []

for cve in data.get("cves", []):
    cve_id = cve.get("cve_id", "")
    if not cve_id:
        continue

    container_deltas = cve.get("container_deltas", {})
    for container_key, delta in container_deltas.items():
        component = CONTAINER_TO_COMPONENT.get(container_key)
        if not component:
            continue
        if delta == "fixed_upstream_not_downstream":
            pending_pairs.append((cve_id, component))
        elif delta == "unknown" and src_index:
            # RPM scanning couldn't determine fix status; check source lockfiles.
            # If the upstream source confirms is_fixed=true, include it.
            src_cve = src_index.get(cve_id, {})
            src_entry = src_cve.get("checked_containers", {}).get(container_key)
            if src_entry and src_entry.get("is_fixed") is True:
                pending_pairs.append((cve_id, component))

# Sort by CVE ID then component for deterministic output
pending_pairs.sort(key=lambda p: (p[0], p[1]))

# ── Write YAML ────────────────────────────────────────────────────────────────

generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

lines = [
    f"# {_PRODUCT_NAME} release notes — CVE entries for upcoming downstream release",
    f"# Generated: {generated_at}",
    f"# Source: {src_path}",
    "#",
    "# These CVEs are fixed upstream but not yet in the current downstream build.",
    "# Paste the 'cves' list into spec.data.releaseNotes.cves in your Konflux",
    "# Release YAML, e.g.:",
    "#",
    "#   spec:",
    "#     data:",
    "#       releaseNotes:",
    "#         type: RHSA",
    "#         cves:",
    "#           - key: CVE-XXXX-XXXXX",
    "#             component: discovery-server",
    "#",
    "cves:",
]

if pending_pairs:
    for cve_id, component in pending_pairs:
        lines.append(f"  - key: {cve_id}")
        lines.append(f"    component: {component}")
else:
    lines.append("  []  # no CVEs found pending upstream-to-downstream release")

out_path = "cve-data/release-notes-cves.yaml"
with open(out_path, "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"Wrote {out_path} ({len(pending_pairs)} entries)", file=sys.stderr)
if not pending_pairs:
    print("Note: no CVEs with delta 'fixed_upstream_not_downstream' found.",
          file=sys.stderr)
