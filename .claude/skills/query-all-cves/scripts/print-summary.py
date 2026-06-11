#!/usr/bin/env python3
"""Print a human-readable summary of cve-data/unified-cves.json."""
import json
import sys

try:
    data = json.load(open("cve-data/unified-cves.json"))
except FileNotFoundError:
    print("Error: cve-data/unified-cves.json not found.", file=sys.stderr)
    sys.exit(1)

s = data["summary"]
print("CVE Report Summary")
print(f"  Total CVEs:    {s['total_cves']}")
print(f"  Fix available: {s['fix_available']}")
print(f"  Fix unknown:   {s['fix_unknown']}")
if s.get("by_severity"):
    severity_str = ", ".join(f"{k}: {v}" for k, v in s["by_severity"].items())
    print(f"  By severity:   {severity_str}")
print(f"  Sources used:  {', '.join(s['sources_used'])}")
print(f"\nFull report: cve-data/unified-cves.json")
