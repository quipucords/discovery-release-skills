#!/usr/bin/env python3
"""Pull container images and query all installed RPM packages.

Pulls discovery-server and discovery-ui images for one or two sets (downstream
and optionally upstream), queries all installed RPMs, writes results to cve-data/,
then removes the images.

All progress messages go to stderr. This script produces no stdout output
(results are written to files). Exits non-zero on any failure.

Usage (single-set — downstream only):
  python3 pull-and-query-rpms.py \\
    --downstream-server-tag 2.5 --downstream-ui-tag 2.6

Usage (dual-set — downstream + upstream comparison):
  python3 pull-and-query-rpms.py \\
    --downstream-server-tag 2.5 --downstream-ui-tag 2.6 \\
    --upstream-server-tag latest --upstream-ui-tag latest
"""
import argparse
import json
import os
import subprocess
import sys
import time

# These constants must match the values in check-cves-in-rpms.py.
# Container keys are derived from the downstream image URLs (path after the registry host).
_DOWNSTREAM_SERVER_IMAGE = os.environ.get("DOWNSTREAM_SERVER_IMAGE", "registry.redhat.io/discovery/discovery-server-rhel9")
_DOWNSTREAM_UI_IMAGE     = os.environ.get("DOWNSTREAM_UI_IMAGE",     "registry.redhat.io/discovery/discovery-ui-rhel9")
_UPSTREAM_SERVER_IMAGE   = os.environ.get("UPSTREAM_SERVER_IMAGE",   "quay.io/quipucords/quipucords")
_UPSTREAM_UI_IMAGE       = os.environ.get("UPSTREAM_UI_IMAGE",       "quay.io/quipucords/quipucords-ui")

SERVER_CONTAINER = _DOWNSTREAM_SERVER_IMAGE.split("/", 1)[1]
UI_CONTAINER     = _DOWNSTREAM_UI_IMAGE.split("/", 1)[1]

DOWNSTREAM_BASE = {
    SERVER_CONTAINER: _DOWNSTREAM_SERVER_IMAGE,
    UI_CONTAINER:     _DOWNSTREAM_UI_IMAGE,
}
UPSTREAM_BASE = {
    SERVER_CONTAINER: _UPSTREAM_SERVER_IMAGE,
    UI_CONTAINER:     _UPSTREAM_UI_IMAGE,
}

parser = argparse.ArgumentParser(
    description="Pull container images and query installed RPMs.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument("--downstream-server-tag", default=None,
                    help=f"Tag for downstream server image ({_DOWNSTREAM_SERVER_IMAGE}:<tag>)")
parser.add_argument("--downstream-ui-tag", default=None,
                    help=f"Tag for downstream UI image ({_DOWNSTREAM_UI_IMAGE}:<tag>)")
parser.add_argument("--upstream-server-tag", default=None,
                    help=f"Tag for upstream server image ({_UPSTREAM_SERVER_IMAGE}:<tag>)")
parser.add_argument("--upstream-ui-tag", default=None,
                    help=f"Tag for upstream UI image ({_UPSTREAM_UI_IMAGE}:<tag>)")
args = parser.parse_args()

# Each pair must be fully specified or fully omitted.
for pair, names in [
    ([args.downstream_server_tag, args.downstream_ui_tag],
     "--downstream-server-tag and --downstream-ui-tag"),
    ([args.upstream_server_tag, args.upstream_ui_tag],
     "--upstream-server-tag and --upstream-ui-tag"),
]:
    if any(pair) and not all(pair):
        print(f"Error: {names} must both be provided or both omitted.", file=sys.stderr)
        sys.exit(1)

sets: dict[str, dict[str, str]] = {}
if args.downstream_server_tag:
    sets["downstream"] = {
        SERVER_CONTAINER: f"{DOWNSTREAM_BASE[SERVER_CONTAINER]}:{args.downstream_server_tag}",
        UI_CONTAINER:     f"{DOWNSTREAM_BASE[UI_CONTAINER]}:{args.downstream_ui_tag}",
    }
if args.upstream_server_tag:
    sets["upstream"] = {
        SERVER_CONTAINER: f"{UPSTREAM_BASE[SERVER_CONTAINER]}:{args.upstream_server_tag}",
        UI_CONTAINER:     f"{UPSTREAM_BASE[UI_CONTAINER]}:{args.upstream_ui_tag}",
    }

if not sets:
    print("Error: specify at least one set of tags (--downstream-*-tag or --upstream-*-tag).",
          file=sys.stderr)
    sys.exit(1)

outfiles: dict[str, dict[str, str]] = {
    sn: {
        SERVER_CONTAINER: f"cve-data/rpms-server-{sn}.txt",
        UI_CONTAINER:     f"cve-data/rpms-ui-{sn}.txt",
    }
    for sn in sets
}

# Ordered flat list; use "::" separator (safe — not in set names or container paths).
all_tasks = [(sn, c) for sn in sets for c in (SERVER_CONTAINER, UI_CONTAINER)]


def make_label(sn: str, c: str) -> str:
    return f"{sn}::{c}"


def parse_label(label: str) -> tuple[str, str]:
    sn, c = label.split("::", 1)
    return sn, c


os.makedirs("cve-data", exist_ok=True)


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def start_procs(tasks):
    """Start a list of (label, cmd) as background Popen processes."""
    running = []
    for label, cmd in tasks:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        running.append((label, proc))
    return running


def wait_procs(running):
    """Wait for all procs and return dict label → (rc, stdout, stderr)."""
    results = {}
    for label, proc in running:
        stdout, stderr = proc.communicate()
        results[label] = (proc.returncode, stdout, stderr)
    return results


# ── Pre-flight: check registry.redhat.io auth only when pulling downstream ────
RH_REGISTRY = "registry.redhat.io"
if "downstream" in sets:
    result = subprocess.run(
        ["podman", "login", "--get-login", RH_REGISTRY],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        log(f"Error: downstream images require authentication to {RH_REGISTRY}.")
        log(f"  Log in with: podman login {RH_REGISTRY}")
        log(f"  Use your Red Hat Customer Portal credentials.")
        log(f"  See: https://access.redhat.com/RegistryAuthentication")
        sys.exit(1)
    log(f"Authenticated to {RH_REGISTRY} as {result.stdout.strip()}")


# ── Phase 1: Pull all images in parallel ─────────────────────────────────────
total_images = len(all_tasks)
log(f"\nPulling {total_images} image(s) in parallel ({len(sets)} set(s))...")
t0 = time.time()

pull_tasks = [
    (make_label(sn, c), ["podman", "pull", sets[sn][c]])
    for sn, c in all_tasks
]
for sn, c in all_tasks:
    log(f"  Starting pull: {sets[sn][c]}")

pull_results = wait_procs(start_procs(pull_tasks))

failed = [lbl for lbl, (rc, _, _) in pull_results.items() if rc != 0]
if failed:
    for lbl in failed:
        sn, c = parse_label(lbl)
        _, _, stderr = pull_results[lbl]
        log(f"  FAILED pull: {sets[sn][c]}\n    {stderr.strip()}")
    sys.exit(1)

for sn, c in all_tasks:
    log(f"  Pulled: {sets[sn][c]}")
log(f"All images pulled in {time.time() - t0:.1f}s.")

# ── Phase 2: Query RPMs from all containers in parallel ──────────────────────
log("\nQuerying installed RPMs in parallel...")
t1 = time.time()

rpm_tasks = [
    (make_label(sn, c),
     ["podman", "run", "--rm", sets[sn][c], "bash", "-c", "rpm -qa | sort"])
    for sn, c in all_tasks
]
for sn, c in all_tasks:
    log(f"  Starting rpm -qa: {sets[sn][c]}")

rpm_results = wait_procs(start_procs(rpm_tasks))

failed = [lbl for lbl, (rc, _, _) in rpm_results.items() if rc != 0]
if failed:
    for lbl in failed:
        sn, c = parse_label(lbl)
        _, _, stderr = rpm_results[lbl]
        log(f"  FAILED rpm -qa: {sets[sn][c]}\n    {stderr.strip()}")
    sys.exit(1)

for sn, c in all_tasks:
    lbl = make_label(sn, c)
    _, stdout, _ = rpm_results[lbl]
    with open(outfiles[sn][c], "w") as f:
        f.write(stdout)
    count = len([line for line in stdout.splitlines() if line.strip()])
    log(f"  Done: {sets[sn][c]} → {outfiles[sn][c]} ({count} packages)")

log(f"RPM queries complete in {time.time() - t1:.1f}s.")


# ── Write checked-images.json for each set ───────────────────────────────────
for sn, containers in sets.items():
    path = f"cve-data/checked-images-{sn}.json"
    with open(path, "w") as f:
        json.dump(containers, f, indent=2)
    log(f"Wrote {path}")

log(f"\nDone in {time.time() - t0:.1f}s total.")
