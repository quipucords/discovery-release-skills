#!/usr/bin/env python3
"""Find UNKNOWN CVE packages and check which are already classified.

Reads the verification output, extracts package names for CVEs that landed
in UNKNOWN status (no RPM data), and cross-references them against
cve-data/package-types.json to show which are already annotated and which
need LLM classification.

Usage:
  python3 find-unknown-packages.py [--comparison] [--set downstream|upstream]
                                   [--package-types-file PATH]

Exit codes:
  0  All UNKNOWN packages are already classified (or there are none)
  1  One or more UNKNOWN packages are missing from the types file
     (stderr lists them so Claude knows what to add)
"""
import argparse
import json
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--comparison", action="store_true")
parser.add_argument("--set", default="downstream", choices=["downstream", "upstream"],
                    dest="set_name")
parser.add_argument("--package-types-file", default="cve-data/package-types.json",
                    metavar="PATH")
args = parser.parse_args()

# ── Load verification data ────────────────────────────────────────────────────

if args.comparison:
    path = "cve-data/comparison.json"
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: {path} not found. Run compare-cve-results.py first.", file=sys.stderr)
        sys.exit(1)
    # In comparison.json the top-level has a "cves" list
    cves = data.get("cves", [])
    unknown_pkg_names = set()
    for cve in cves:
        if cve.get("delta") == "unknown":
            for name in cve.get("package_names", []):
                if name:
                    unknown_pkg_names.add(name)
else:
    path = f"cve-data/verified-cves-{args.set_name}.json"
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: {path} not found.", file=sys.stderr)
        sys.exit(1)
    cves = data.get("cves", [])
    unknown_pkg_names = set()
    for cve in cves:
        for entry in cve.get("checked_containers", {}).values():
            if not entry.get("package_found") and not entry.get("searched_names"):
                for name in cve.get("package_names", []):
                    if name:
                        unknown_pkg_names.add(name)

# ── Load existing package types ───────────────────────────────────────────────

pkg_types: dict = {}
try:
    with open(args.package_types_file) as f:
        pkg_types = json.load(f)
except FileNotFoundError:
    pass  # file may not exist yet; all packages will be unclassified

# ── Cross-reference ───────────────────────────────────────────────────────────

if not unknown_pkg_names:
    print("No UNKNOWN packages found. Skipping classification step.", file=sys.stderr)
    sys.exit(0)

already_classified = {}
unclassified = []

for name in sorted(unknown_pkg_names):
    info = pkg_types.get(name) or pkg_types.get(name.lower())
    if info:
        already_classified[name] = info
    else:
        unclassified.append(name)

# ── Report ────────────────────────────────────────────────────────────────────

print(f"UNKNOWN packages found: {len(unknown_pkg_names)}", file=sys.stderr)

if already_classified:
    print(f"Already classified ({len(already_classified)}):", file=sys.stderr)
    for name, info in already_classified.items():
        print(f"  {name} → {info['ecosystem']}: {info['description'][:70]}", file=sys.stderr)

if unclassified:
    print(f"Need LLM classification ({len(unclassified)}):", file=sys.stderr)
    for name in unclassified:
        print(f"  {name}", file=sys.stderr)
    print(
        f"\nAdd the above package(s) to {args.package_types_file} with ecosystem and "
        f"description fields, then re-run generate-html-report.py.",
        file=sys.stderr,
    )
    # Emit the unclassified names as JSON to stdout for easy consumption
    print(json.dumps(unclassified))
    sys.exit(1)

print("All UNKNOWN packages are already classified.", file=sys.stderr)
sys.exit(0)
