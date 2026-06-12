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
SERVER_CONTAINER = "discovery/discovery-server-rhel9"
UI_CONTAINER     = "discovery/discovery-ui-rhel9"

DOWNSTREAM_BASE = {
    SERVER_CONTAINER: "registry.redhat.io/discovery/discovery-server-rhel9",
    UI_CONTAINER:     "registry.redhat.io/discovery/discovery-ui-rhel9",
}
UPSTREAM_BASE = {
    SERVER_CONTAINER: "quay.io/quipucords/quipucords",
    UI_CONTAINER:     "quay.io/quipucords/quipucords-ui",
}

parser = argparse.ArgumentParser(
    description="Pull Discovery container images and query installed RPMs.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument("--downstream-server-tag", default="latest",
                    help="Tag for downstream discovery-server (default: latest)")
parser.add_argument("--downstream-ui-tag", default="latest",
                    help="Tag for downstream discovery-ui (default: latest)")
parser.add_argument("--upstream-server-tag", default=None,
                    help="Tag for upstream discovery-server (enables dual-set mode)")
parser.add_argument("--upstream-ui-tag", default=None,
                    help="Tag for upstream discovery-ui (enables dual-set mode)")
args = parser.parse_args()

upstream_tags = [args.upstream_server_tag, args.upstream_ui_tag]
if any(upstream_tags) and not all(upstream_tags):
    print("Error: --upstream-server-tag and --upstream-ui-tag must both be provided or both omitted.",
          file=sys.stderr)
    sys.exit(1)

dual_set = all(t is not None for t in upstream_tags)

sets: dict[str, dict[str, str]] = {
    "downstream": {
        SERVER_CONTAINER: f"{DOWNSTREAM_BASE[SERVER_CONTAINER]}:{args.downstream_server_tag}",
        UI_CONTAINER:     f"{DOWNSTREAM_BASE[UI_CONTAINER]}:{args.downstream_ui_tag}",
    }
}
if dual_set:
    sets["upstream"] = {
        SERVER_CONTAINER: f"{UPSTREAM_BASE[SERVER_CONTAINER]}:{args.upstream_server_tag}",
        UI_CONTAINER:     f"{UPSTREAM_BASE[UI_CONTAINER]}:{args.upstream_ui_tag}",
    }

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


def cleanup_images(pulled: list[str]) -> None:
    """Remove images that were successfully pulled."""
    for img in pulled:
        log(f"  Removing: {img}")
        subprocess.run(["podman", "rmi", img], capture_output=True)
        log(f"  Removed:  {img}")


# ── Pre-flight: downstream images always require registry.redhat.io auth ──────
RH_REGISTRY = "registry.redhat.io"
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
pulled_images = [sets[sn][c] for sn, c in all_tasks]

try:
    # ── Phase 2: Query RPMs from all containers in parallel ───────────────────
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

finally:
    # ── Phase 3: Remove pulled images (always, even on unexpected failure) ────
    log("\nRemoving pulled images...")
    cleanup_images(pulled_images)


# ── Write checked-images.json for each set ───────────────────────────────────
for sn, containers in sets.items():
    path = f"cve-data/checked-images-{sn}.json"
    with open(path, "w") as f:
        json.dump(containers, f, indent=2)
    log(f"Wrote {path}")

log(f"\nDone in {time.time() - t0:.1f}s total.")
