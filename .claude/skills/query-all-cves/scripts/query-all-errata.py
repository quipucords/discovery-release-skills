#!/usr/bin/env python3
"""Query errata for all advisory IDs in cve-data/advisory-ids.txt, in parallel.

Each advisory is queried concurrently via subprocess.Popen. Output is written
to cve-data/errata-<safe-id>.json. Failures are reported but do not abort the
run — partial errata data is still useful for the merge step.
"""
import subprocess
import sys
import time

try:
    with open("cve-data/advisory-ids.txt") as f:
        ids = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    print("Error: cve-data/advisory-ids.txt not found. Run extract-advisory-ids.py first.",
          file=sys.stderr)
    sys.exit(1)

if not ids:
    print("No advisory IDs to query.", file=sys.stderr)
    sys.exit(0)

print(f"Phase 2: querying {len(ids)} advisory IDs in parallel...", flush=True)
t0 = time.time()

script = ".claude/skills/query-errata-advisory/scripts/query-errata-advisory.py"

# File handles are opened here and kept open for the duration of each Popen
# subprocess — this is intentional. They are closed explicitly in the wait loop.
handles = []
procs = []
for advisory_id in ids:
    safe = "".join(c if c.isalnum() else "-" for c in advisory_id)
    fh = open(f"cve-data/errata-{safe}.json", "w")  # noqa: WPS515 (Popen pattern)
    handles.append(fh)
    procs.append((advisory_id, subprocess.Popen(["uv", "run", script, advisory_id], stdout=fh)))

failed = []
for fh, (advisory_id, proc) in zip(handles, procs):
    rc = proc.wait()
    fh.close()
    if rc != 0:
        failed.append(advisory_id)

if failed:
    print(f"Warning: {len(failed)} errata queries failed: {', '.join(failed)}", file=sys.stderr)

succeeded = len(ids) - len(failed)
print(f"Phase 2 complete in {time.time() - t0:.1f}s: {succeeded}/{len(ids)} succeeded.", flush=True)
