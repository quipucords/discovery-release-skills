#!/usr/bin/env python3
"""Run merge-cve-data with all collected input files.

Resolves cve-data/errata-*.json via glob in Python so Claude does not need
to expand shell wildcards — avoiding the approval prompts that glob arguments
in Bash commands typically trigger.
"""
import glob
import subprocess
import sys

errata_files = sorted(glob.glob("cve-data/errata-*.json"))
if not errata_files:
    print("Warning: no errata files found in cve-data/ — merge will proceed without them.",
          file=sys.stderr)

cmd = [
    "uv", "run",
    ".claude/skills/merge-cve-data/scripts/merge-cve-data.py",
    "--catalog",  "cve-data/catalog.json",
    "--prograde", "cve-data/prograde-advisories.json",
    "--jira",     "cve-data/jira.json",
]
if errata_files:
    cmd += ["--errata"] + errata_files

with open("cve-data/unified-cves.json", "w") as out:
    result = subprocess.run(cmd, stdout=out)

if result.returncode != 0:
    print("Error: merge-cve-data failed.", file=sys.stderr)
    sys.exit(1)

print("Merge complete → cve-data/unified-cves.json", file=sys.stderr)
