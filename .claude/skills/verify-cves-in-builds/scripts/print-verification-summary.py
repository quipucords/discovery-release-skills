#!/usr/bin/env python3
"""Print a human-readable summary of cve-data/verified-cves.json.

The summary is written to stdout. Errors go to stderr.
Exits non-zero if the input file is missing or unreadable.
"""
import json
import sys

SEVERITY_ORDER = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1, "Unknown": 0}

try:
    data = json.load(open("cve-data/verified-cves.json"))
except FileNotFoundError:
    print("Error: cve-data/verified-cves.json not found. Run check-cves-in-rpms.py first.",
          file=sys.stderr)
    sys.exit(1)
except json.JSONDecodeError as e:
    print(f"Error: cve-data/verified-cves.json is not valid JSON: {e}", file=sys.stderr)
    sys.exit(1)

verification = data.get("verification", {})
images = verification.get("images", {})
skipped_nvras = verification.get("skipped_nvras", {})
vsummary = data.get("verification_summary", {})
cves = data.get("cves", [])

print("CVE Build Verification Report")
print(f"  Verified at: {data.get('verified_at', 'unknown')}")
print()

# ── Per-container counts ──────────────────────────────────────────────────────
for container, image in images.items():
    s = vsummary.get(container, {})
    print(f"  {container}")
    print(f"    Checked image:          {image}")
    print(f"    Fixed in build:         {s.get('fixed', 0)}")
    print(f"    NOT fixed in build:     {s.get('not_fixed', 0)}")
    print(f"    Could not verify:       {s.get('not_found', 0)}  ← package not found in container")
    print(f"    Fix status unknown:     {s.get('unknown', 0)}  ← found but no fix NVR available")
    print()

sev_key = lambda c: -SEVERITY_ORDER.get(c.get("severity") or "Unknown", 0)

# ── Per-container detail sections ────────────────────────────────────────────
for container in images:
    unfixed       = []
    not_found     = []
    status_unknown = []

    for cve in cves:
        entry = cve.get("checked_containers", {}).get(container, {})
        is_fixed = entry.get("is_fixed")
        if is_fixed is False:
            unfixed.append(cve)
        elif entry.get("package_found") is False and entry.get("searched_names"):
            not_found.append(cve)
        elif is_fixed is None and entry.get("package_found") is True:
            status_unknown.append(cve)

    if not unfixed and not not_found and not status_unknown:
        print(f"  {container}: all checked CVEs are fixed. ✓")
        print()
        continue

    if unfixed:
        unfixed.sort(key=sev_key)
        print(f"  {container}: {len(unfixed)} unfixed CVE(s):")
        for cve in unfixed:
            entry = cve["checked_containers"][container]
            installed = ", ".join(entry.get("installed_nvras") or ["?"])
            fixed_nvr = entry.get("minimum_fixed_nvr") or "?"
            print(f"    [{cve.get('severity', '?'):9s}] {cve['cve_id']}")
            print(f"               installed: {installed}")
            print(f"               needs:     {fixed_nvr}")
        print()

    if not_found:
        not_found.sort(key=sev_key)
        print(f"  {container}: {len(not_found)} CVE(s) could not be verified — "
              f"package not found in container, check manually:")
        for cve in not_found:
            entry = cve["checked_containers"][container]
            names = ", ".join(entry.get("searched_names") or ["?"])
            print(f"    [{cve.get('severity', '?'):9s}] {cve['cve_id']}")
            print(f"               searched for: {names}")
        print()

    if status_unknown:
        status_unknown.sort(key=sev_key)
        print(f"  {container}: {len(status_unknown)} CVE(s) found in container "
              f"but fix version unknown:")
        for cve in status_unknown:
            entry = cve["checked_containers"][container]
            installed = ", ".join(entry.get("installed_nvras") or ["?"])
            print(f"    [{cve.get('severity', '?'):9s}] {cve['cve_id']}")
            print(f"               installed: {installed}")
            print(f"               fixed NVR: unknown")
        print()

# ── Skipped NVRA lines note ───────────────────────────────────────────────────
any_skipped = {c: lines for c, lines in skipped_nvras.items() if lines}
if any_skipped:
    print("  Warning — RPM entries that could not be parsed and were skipped:")
    for container, lines in any_skipped.items():
        print(f"    {container}:")
        for line in lines:
            print(f"      {line}")
    print(f"    These entries do not follow the standard name-version-release.arch")
    print(f"    format and could not be included in CVE verification. Verify")
    print(f"    independently whether any of these are relevant to your CVEs.")
    print()

print(f"Full report: cve-data/verified-cves.json")
