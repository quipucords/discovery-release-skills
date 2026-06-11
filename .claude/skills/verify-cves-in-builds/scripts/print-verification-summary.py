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

sev_key = lambda c: -SEVERITY_ORDER.get(c.get("severity") or "Unknown", 0)

# ── Pre-collect all action-required items across all containers ───────────────
any_skipped = {c: lines for c, lines in skipped_nvras.items() if lines}

# CVEs where the container IS affected but no RPM package data exists to check
all_no_pkg_data = []   # list of (cve, container) pairs
for container in images:
    for cve in cves:
        entry = cve.get("checked_containers", {}).get(container, {})
        if (entry.get("package_found") is False
                and not entry.get("searched_names")
                and container in cve.get("affected_containers", [])):
            all_no_pkg_data.append((cve, container))

print("CVE Build Verification Report")
print(f"  Verified at: {data.get('verified_at', 'unknown')}")
print()

# ── ACTION REQUIRED at the top — everything needing manual attention ──────────
# This block appears before all CVE detail so it cannot be missed or dropped.
if any_skipped or all_no_pkg_data:
    print("  *** ACTION REQUIRED — Manual verification needed for the following ***")
    print()

    if any_skipped:
        print("  RPM entries that could not be parsed and were excluded from verification:")
        print("  (Check whether any are relevant to the CVEs in this report.)")
        print()
        for container, lines in any_skipped.items():
            print(f"    {container.split('/')[-1]}:")
            for line in lines:
                print(f"      {line}")
        print()

    if all_no_pkg_data:
        print("  CVEs marked UNKNOWN — affect the container but have no RPM package data:")
        print("  (May be non-RPM dependencies such as npm or Python packages.")
        print("   Cannot be verified automatically. Investigate each one manually.)")
        print()
        for cve, container in sorted(all_no_pkg_data, key=lambda x: -SEVERITY_ORDER.get(x[0].get("severity") or "Unknown", 0)):
            sev = cve.get("severity") or "?"
            print(f"    [{sev:9s}] {cve['cve_id']}  ({container.split('/')[-1]})")
            print(f"               {cve.get('cve_link', '')}")
        print()

    print("  *** END ACTION REQUIRED ***")
    print()

# ── Per-container counts ──────────────────────────────────────────────────────
for container, image in images.items():
    s = vsummary.get(container, {})
    print(f"  {container}")
    print(f"    Checked image:          {image}")
    print(f"    Fixed in build:         {s.get('fixed', 0)}")
    print(f"    NOT fixed in build:     {s.get('not_fixed', 0)}")
    print(f"    Could not verify:       {s.get('not_found', 0)}  ← package not found in container")
    print(f"    UNKNOWN (no RPM data):  {s.get('no_package_data', 0)}  ← see ACTION REQUIRED above")
    print(f"    Fix status unknown:     {s.get('unknown', 0)}  ← found but no fix NVR available")
    print()

# ── Per-container detail sections ────────────────────────────────────────────
for container in images:
    unfixed        = []
    not_found      = []
    no_pkg_data    = []
    status_unknown = []

    for cve in cves:
        entry = cve.get("checked_containers", {}).get(container, {})
        is_fixed = entry.get("is_fixed")
        if is_fixed is False:
            unfixed.append(cve)
        elif entry.get("package_found") is False and entry.get("searched_names"):
            not_found.append(cve)
        elif entry.get("package_found") is False and not entry.get("searched_names") \
                and container in cve.get("affected_containers", []):
            no_pkg_data.append(cve)
        elif is_fixed is None and entry.get("package_found") is True:
            status_unknown.append(cve)

    if not unfixed and not not_found and not no_pkg_data and not status_unknown:
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
            print(f"    [{(cve.get('severity') or '?'):9s}] {cve['cve_id']}")
            print(f"               installed: {installed}")
            print(f"               needs:     {fixed_nvr}")
        print()

    if not_found:
        not_found.sort(key=sev_key)
        print(f"  {container}: {len(not_found)} CVE(s) could not be verified —"
              f" package not found in container, check manually:")
        for cve in not_found:
            entry = cve["checked_containers"][container]
            names = ", ".join(entry.get("searched_names") or ["?"])
            print(f"    [{(cve.get('severity') or '?'):9s}] {cve['cve_id']}")
            print(f"               searched for: {names}")
        print()

    if no_pkg_data:
        no_pkg_data.sort(key=sev_key)
        print(f"  {container}: {len(no_pkg_data)} CVE(s) marked UNKNOWN (see ACTION REQUIRED above):")
        for cve in no_pkg_data:
            print(f"    [{(cve.get('severity') or '?'):9s}] {cve['cve_id']}")
        print()

    if status_unknown:
        status_unknown.sort(key=sev_key)
        print(f"  {container}: {len(status_unknown)} CVE(s) found in container"
              f" but fix version unknown:")
        for cve in status_unknown:
            entry = cve["checked_containers"][container]
            installed = ", ".join(entry.get("installed_nvras") or ["?"])
            print(f"    [{(cve.get('severity') or '?'):9s}] {cve['cve_id']}")
            print(f"               installed: {installed}")
            print(f"               fixed NVR: unknown")
        print()

print(f"Full report: cve-data/verified-cves.json")
