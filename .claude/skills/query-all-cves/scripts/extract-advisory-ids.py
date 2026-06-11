#!/usr/bin/env python3
"""Extract and deduplicate advisory IDs from catalog.json and prograde-advisories.json.

Writes cve-data/advisory-ids.txt with one ID per line, sorted.

Advisory ID formats differ by source:
  catalog:  RHSA-format  (e.g. RHSA-2026:12441)
  prograde: numeric      (e.g. 165721)
Both formats are accepted by query-errata-advisory. Deduplication here prevents
redundant API calls when the same advisory appears in both sources.
"""
import json
import sys

try:
    with open("cve-data/catalog.json") as f:
        catalog = json.load(f)
    with open("cve-data/prograde-advisories.json") as f:
        prograde = json.load(f)
except FileNotFoundError as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)

ids = set()
for cve in catalog.get("cves", []):
    if cve.get("advisory_id"):
        ids.add(cve["advisory_id"])
for advisory in prograde.get("advisories", []):
    if advisory.get("advisory_id"):
        ids.add(str(advisory["advisory_id"]))

with open("cve-data/advisory-ids.txt", "w") as f:
    for advisory_id in sorted(ids):
        f.write(advisory_id + "\n")

print(f"Extracted {len(ids)} unique advisory IDs → cve-data/advisory-ids.txt", file=sys.stderr)
