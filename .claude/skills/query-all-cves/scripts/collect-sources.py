#!/usr/bin/env python3
"""Run the three independent CVE source queries in parallel.

Uses subprocess.Popen to launch all three concurrently. Each script's stdout
is redirected to its data file; stderr flows to the terminal as progress logs.
This script never mixes stderr into a data file — the file handles passed to
Popen are stdout-only, making 2>&1 corruption impossible from this path.

Usage: python3 collect-sources.py [--since YYYY-MM-DD]
"""
import datetime
import os
import subprocess
import sys
import time

since = datetime.date.today() - datetime.timedelta(days=90)
if "--since" in sys.argv:
    since = sys.argv[sys.argv.index("--since") + 1]
else:
    since = since.isoformat()

os.makedirs("cve-data", exist_ok=True)

skills = ".claude/skills"
jobs = [
    ("catalog", ["uv", "run", f"{skills}/query-redhat-catalog/scripts/query-redhat-catalog.py"],
     "cve-data/catalog.json"),
    ("gmail",   ["uv", "run", f"{skills}/query-gmail/scripts/query-gmail.py",
                 "--label", "alerts/prograde", "--since", since],
     "cve-data/prograde-emails.json"),
    ("jira",    ["uv", "run", f"{skills}/query-jira-cves/scripts/query-jira-cves.py",
                 "--summary-contains", "CVE"],
     "cve-data/jira.json"),
]

print("Phase 1: collecting from all sources in parallel...", flush=True)
t0 = time.time()

handles = []
procs = []
for name, cmd, outfile in jobs:
    print(f"  Starting: {name}", flush=True)
    fh = open(outfile, "w")
    handles.append(fh)
    procs.append((name, subprocess.Popen(cmd, stdout=fh)))

failed = []
for fh, (name, proc) in zip(handles, procs):
    rc = proc.wait()
    fh.close()
    if rc != 0:
        failed.append(name)
        print(f"  FAILED:  {name} (exit {rc})", file=sys.stderr, flush=True)
    else:
        print(f"  Done:    {name}", flush=True)

if failed:
    print(f"\nError: {len(failed)} source(s) failed: {', '.join(failed)}", file=sys.stderr)
    sys.exit(1)

print(f"\nPhase 1 complete in {time.time() - t0:.1f}s.", flush=True)
