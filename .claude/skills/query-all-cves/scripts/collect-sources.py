#!/usr/bin/env python3
"""Run the three independent CVE source queries in parallel.

Uses subprocess.Popen to launch all three concurrently. Each script's stdout
is redirected to its data file; stderr flows to the terminal as progress logs.
This script never mixes stderr into a data file — the file handles passed to
Popen are stdout-only, making 2>&1 corruption impossible from this path.

Usage:
  python3 collect-sources.py [--since YYYY-MM-DD]
                              [--since-last-release]
                              [--server-tag TAG] [--ui-tag TAG]
                              [--skip-gmail]

  --since               Earliest date to fetch (default: 90 days ago). Applied
                        to Gmail and JIRA queries.
  --since-last-release  Derive --since from the catalog: query both containers'
                        latest image publication dates and use the earlier one.
                        Mutually exclusive with --since.
  --server-tag          Image tag to query for discovery-server in the Red Hat
                        Catalog (default: latest published tag).
  --ui-tag              Image tag to query for discovery-ui in the Red Hat
                        Catalog (default: latest published tag).
  --skip-gmail          Skip the Gmail/Prograde query entirely. Writes an empty
                        prograde-emails.json so downstream steps run unchanged.
                        Use when Prograde emails are unavailable or unwanted.
  --use-provided-prograde
                        Skip the Gmail query but read cve-data/prograde-emails.json
                        from disk as-is. Use when a teammate has already exported
                        the file and transferred it to you. Exits non-zero if the
                        file is missing or empty.

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

_CATALOG_SERVER_NAME = os.environ.get("CATALOG_SERVER_NAME", "discovery-server")
_CATALOG_UI_NAME     = os.environ.get("CATALOG_UI_NAME",     "discovery-ui")

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--since", default=None)
parser.add_argument("--since-last-release", action="store_true", default=False)
parser.add_argument("--server-tag", default=None)
parser.add_argument("--ui-tag", default=None)
parser.add_argument("--skip-gmail", action="store_true", default=False)
parser.add_argument("--use-provided-prograde", action="store_true", default=False)
args = parser.parse_args()

if args.skip_gmail and args.use_provided_prograde:
    print("Error: --skip-gmail and --use-provided-prograde are mutually exclusive.", file=sys.stderr)
    sys.exit(1)

if args.since and args.since_last_release:
    print("Error: --since and --since-last-release are mutually exclusive.", file=sys.stderr)
    sys.exit(1)

if args.since_last_release:
    release_date_script = ".claude/skills/query-redhat-catalog/scripts/get-catalog-release-date.py"
    print("Fetching last downstream release date from Red Hat Catalog...", flush=True)
    result = subprocess.run(["uv", "run", release_date_script], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: failed to get release date from catalog.\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    # stderr was already logged to the terminal via capture; re-emit it
    if result.stderr:
        print(result.stderr, end="", flush=True)
    since = result.stdout.strip()
    print(f"Using --since {since} (last downstream release date).", flush=True)
else:
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
    for container, tag in [(_CATALOG_SERVER_NAME, args.server_tag),
                            (_CATALOG_UI_NAME,     args.ui_tag)]:
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
elif args.use_provided_prograde:
    prograde_path = "cve-data/prograde-emails.json"
    if not os.path.exists(prograde_path):
        print(f"Error: --use-provided-prograde set but {prograde_path} not found.\n"
              "Ask a teammate who receives Prograde emails to export it for you.",
              file=sys.stderr)
        sys.exit(1)
    with open(prograde_path) as f:
        data = json.load(f)
    if not data.get("messages"):
        print(f"Error: {prograde_path} exists but contains no messages.\n"
              "Ask a teammate to re-export it with at least one Prograde email.",
              file=sys.stderr)
        sys.exit(1)
    print(f"  Using provided prograde-emails.json ({len(data['messages'])} messages).", flush=True)
    parallel_jobs = [
        ("jira", ["uv", "run", f"{skills}/query-jira-cves/scripts/query-jira-cves.py",
                  "--summary-contains", "CVE"],
         "cve-data/jira.json"),
    ]
else:
    prograde_label = os.environ.get("PROGRADE_LABEL", "")
    gmail_cmd = ["uv", "run", f"{skills}/query-gmail/scripts/query-gmail.py"]
    if prograde_label:
        gmail_cmd += ["--label", prograde_label]
    gmail_cmd += ["--since", since]
    parallel_jobs = [
        ("gmail", gmail_cmd, "cve-data/prograde-emails.json"),
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
