#!/usr/bin/env python3
"""Query errata for all advisory IDs in cve-data/advisory-ids.txt, in parallel.

Each advisory is queried concurrently via subprocess.Popen. Output is written
to cve-data/errata-<safe-id>.json. Failures are reported but do not abort the
run — partial errata data is still useful for the merge step.
"""
import subprocess
import sys

try:
    ids = [line.strip() for line in open("cve-data/advisory-ids.txt") if line.strip()]
except FileNotFoundError:
    print("Error: cve-data/advisory-ids.txt not found. Run extract-advisory-ids.py first.",
          file=sys.stderr)
    sys.exit(1)

if not ids:
    print("No advisory IDs to query.")
    sys.exit(0)

print(f"Querying {len(ids)} advisory IDs in parallel...")

script = ".claude/skills/query-errata-advisory/scripts/query-errata-advisory.py"

handles = []
procs = []
for id in ids:
    safe = "".join(c if c.isalnum() else "-" for c in id)
    fh = open(f"cve-data/errata-{safe}.json", "w")
    handles.append(fh)
    procs.append((id, subprocess.Popen(["uv", "run", script, id], stdout=fh)))

failed = []
for fh, (id, proc) in zip(handles, procs):
    rc = proc.wait()
    fh.close()
    if rc != 0:
        failed.append(id)

if failed:
    print(f"Warning: {len(failed)} errata queries failed: {', '.join(failed)}", file=sys.stderr)

succeeded = len(ids) - len(failed)
print(f"Errata phase complete: {succeeded}/{len(ids)} succeeded.")
