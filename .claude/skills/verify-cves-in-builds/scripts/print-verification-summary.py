#!/usr/bin/env python3
"""Print a human-readable summary of cve-data/verified-cves.json."""
import json
import sys

SEVERITY_ORDER = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1, "Unknown": 0}

try:
    data = json.load(open("cve-data/verified-cves.json"))
except FileNotFoundError:
    print("Error: cve-data/verified-cves.json not found. Run check-cves-in-rpms.py first.",
          file=sys.stderr)
    sys.exit(1)

verification = data.get("verification", {})
images = verification.get("images", {})
vsummary = data.get("verification_summary", {})
cves = data.get("cves", [])

print("CVE Build Verification Report")
print(f"  Verified at: {data.get('verified_at', 'unknown')}")
print()

for container, image in images.items():
    s = vsummary.get(container, {})
    print(f"  {container}")
    print(f"    Checked image: {image}")
    print(f"    Packages found:    {s.get('found', 0)}")
    print(f"    Fixed in build:    {s.get('fixed', 0)}")
    print(f"    NOT fixed in build:{s.get('not_fixed', 0)}")
    print(f"    Fix status unknown:{s.get('unknown', 0)}")
    print()

# List unfixed CVEs per container, sorted by severity
for container in images:
    unfixed = []
    for cve in cves:
        entry = cve.get("checked_containers", {}).get(container, {})
        if entry.get("is_fixed") is False:
            unfixed.append(cve)

    if not unfixed:
        print(f"  {container}: no unfixed CVEs found in build.")
        continue

    unfixed.sort(key=lambda c: -SEVERITY_ORDER.get(c.get("severity") or "Unknown", 0))
    print(f"  {container}: {len(unfixed)} unfixed CVE(s):")
    for cve in unfixed:
        entry = cve["checked_containers"][container]
        installed = ", ".join(entry.get("installed_nvras") or ["?"])
        fixed_nvr = entry.get("minimum_fixed_nvr") or "?"
        print(f"    [{cve.get('severity', '?'):9s}] {cve['cve_id']}")
        print(f"               installed: {installed}")
        print(f"               needs:     {fixed_nvr}")
    print()

print(f"Full report: cve-data/verified-cves.json")
