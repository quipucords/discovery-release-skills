#!/usr/bin/env python3
"""Run the three independent CVE source queries in parallel.

Uses subprocess.Popen to launch all three concurrently. Each script's stdout
is redirected to its data file; stderr flows to the terminal as progress logs.
This script never mixes stderr into a data file — the file handles passed to
Popen are stdout-only, making 2>&1 corruption impossible from this path.

Usage:
  python3 collect-sources.py [--since YYYY-MM-DD]
                              [--server-tag TAG] [--ui-tag TAG]
                              [--skip-gmail]

  --since         Earliest date to fetch (default: 90 days ago). Applied to
                  Gmail and JIRA queries.
  --server-tag    Image tag to query for discovery-server in the Red Hat
                  Catalog (default: latest published tag).
  --ui-tag        Image tag to query for discovery-ui in the Red Hat Catalog
                  (default: latest published tag).
  --skip-gmail    Skip the Gmail/Prograde query entirely. Writes an empty
                  prograde-emails.json so downstream steps run unchanged.
                  Use when Prograde emails are unavailable or unwanted.

  When --server-tag or --ui-tag are provided, the catalog is queried once per
  container and the results are merged into cve-data/catalog.json.
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
import time

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--since", default=None)
parser.add_argument("--server-tag", default=None)
parser.add_argument("--ui-tag", default=None)
parser.add_argument("--skip-gmail", action="store_true", default=False)
args = parser.parse_args()

since = args.since or (datetime.date.today() - datetime.timedelta(days=90)).isoformat()

os.makedirs("cve-data", exist_ok=True)

skills = ".claude/skills"
catalog_script = f"{skills}/query-redhat-catalog/scripts/query-redhat-catalog.py"

# Build the catalog command. If per-container tags are requested, we query
# each container separately (sequentially, before the parallel phase) and
# merge the results into a single catalog.json.
def collect_catalog():
    if not args.server_tag and not args.ui_tag:
        cmd = ["uv", "run", catalog_script]
        with open("cve-data/catalog.json", "w") as out:
            result = subprocess.run(cmd, capture_output=False, stdout=out)
        return result.returncode == 0

    # Per-container queries
    combined = {"total": 0, "cves": []}
    for container, tag in [("discovery-server", args.server_tag),
                            ("discovery-ui",     args.ui_tag)]:
        cmd = ["uv", "run", catalog_script, "--container", container]
        if tag:
            cmd += ["--tag", tag]
            print(f"  Querying catalog: {container} (tag: {tag})", flush=True)
        else:
            print(f"  Querying catalog: {container} (default tag)", flush=True)
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  FAILED: catalog/{container}", file=sys.stderr, flush=True)
            return False
        data = json.loads(result.stdout)
        combined["cves"].extend(data.get("cves", []))
        combined["total"] += data.get("total", 0)

    with open("cve-data/catalog.json", "w") as out:
        json.dump(combined, out, indent=2)
    return True

# Parallel jobs for gmail (optional) and jira
if args.skip_gmail:
    print("  Skipping Gmail/Prograde (--skip-gmail set).", flush=True)
    with open("cve-data/prograde-emails.json", "w") as f:
        json.dump({"messages": []}, f)
    parallel_jobs = [
        ("jira", ["uv", "run", f"{skills}/query-jira-cves/scripts/query-jira-cves.py",
                  "--summary-contains", "CVE"],
         "cve-data/jira.json"),
    ]
else:
    parallel_jobs = [
        ("gmail", ["uv", "run", f"{skills}/query-gmail/scripts/query-gmail.py",
                   "--label", "alerts/prograde", "--since", since],
         "cve-data/prograde-emails.json"),
        ("jira",  ["uv", "run", f"{skills}/query-jira-cves/scripts/query-jira-cves.py",
                   "--summary-contains", "CVE"],
         "cve-data/jira.json"),
    ]

print("Phase 1: collecting from all sources...", flush=True)
t0 = time.time()

# Catalog (may be sequential if per-container tags requested)
if args.server_tag or args.ui_tag:
    print("  Starting: catalog (per-container)", flush=True)
    if not collect_catalog():
        print("\nError: catalog collection failed.", file=sys.stderr)
        sys.exit(1)
    print("  Done:    catalog", flush=True)
    # Now launch gmail and jira in parallel
    handles, procs = [], []
    for name, cmd, outfile in parallel_jobs:
        print(f"  Starting: {name}", flush=True)
        fh = open(outfile, "w")
        handles.append(fh)
        procs.append((name, subprocess.Popen(cmd, stdout=fh)))
else:
    # All three in parallel
    all_jobs = [("catalog", ["uv", "run", catalog_script], "cve-data/catalog.json")] + parallel_jobs
    handles, procs = [], []
    for name, cmd, outfile in all_jobs:
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
