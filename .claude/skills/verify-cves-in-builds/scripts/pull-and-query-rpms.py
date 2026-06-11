#!/usr/bin/env python3
"""Pull container images and query all installed RPM packages.

Pulls discovery-server and discovery-ui images in parallel, queries all
installed RPMs from each container in a single run per image, writes the
results to cve-data/, then removes the images.

All progress messages go to stderr. This script produces no stdout output
(results are written to files). Exits non-zero on any failure.

Usage:
  python3 pull-and-query-rpms.py \\
    --server-image quay.io/quipucords/quipucords:latest \\
    --ui-image quay.io/quipucords/quipucords-ui:latest
"""
import argparse
import json
import os
import subprocess
import sys
import time

SERVER_CONTAINER = "discovery/discovery-server-rhel9"
UI_CONTAINER = "discovery/discovery-ui-rhel9"

parser = argparse.ArgumentParser()
parser.add_argument("--server-image", required=True,
                    help="Image to check for discovery-server (e.g. quay.io/quipucords/quipucords:latest)")
parser.add_argument("--ui-image", required=True,
                    help="Image to check for discovery-ui (e.g. quay.io/quipucords/quipucords-ui:latest)")
args = parser.parse_args()

images = {
    SERVER_CONTAINER: args.server_image,
    UI_CONTAINER:     args.ui_image,
}
outfiles = {
    SERVER_CONTAINER: "cve-data/rpms-server.txt",
    UI_CONTAINER:     "cve-data/rpms-ui.txt",
}

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
    """Remove images that were successfully pulled, logging each removal."""
    for img in pulled:
        log(f"  Removing: {img}")
        subprocess.run(["podman", "rmi", img], capture_output=True)
        log(f"  Removed:  {img}")


# ── Phase 1: Pull both images in parallel ────────────────────────────────────
log("Pulling container images in parallel...")
t0 = time.time()

pull_tasks = [(c, ["podman", "pull", img]) for c, img in images.items()]
for c, _ in pull_tasks:
    log(f"  Starting pull: {images[c]}")

pull_results = wait_procs(start_procs(pull_tasks))

failed = [c for c, (rc, _, _) in pull_results.items() if rc != 0]
if failed:
    for c in failed:
        _, _, stderr = pull_results[c]
        log(f"  FAILED pull: {images[c]}\n    {stderr.strip()}")
    sys.exit(1)

for c in images:
    log(f"  Pulled:  {images[c]}")
log(f"All images pulled in {time.time() - t0:.1f}s.")
pulled_images = list(images.values())


# ── Phase 2: Query RPMs from both containers in parallel ─────────────────────
log("\nQuerying installed RPMs in parallel...")
t1 = time.time()

rpm_tasks = [
    (c, ["podman", "run", "--rm", img, "bash", "-c", "rpm -qa | sort"])
    for c, img in images.items()
]
for c, _ in rpm_tasks:
    log(f"  Starting rpm -qa: {images[c]}")

rpm_results = wait_procs(start_procs(rpm_tasks))

failed = [c for c, (rc, _, _) in rpm_results.items() if rc != 0]
if failed:
    for c in failed:
        _, _, stderr = rpm_results[c]
        log(f"  FAILED rpm -qa: {images[c]}\n    {stderr.strip()}")
    log("\nCleaning up pulled images before exit...")
    cleanup_images(pulled_images)
    sys.exit(1)

for c, (_, stdout, _) in rpm_results.items():
    with open(outfiles[c], "w") as f:
        f.write(stdout)
    count = len([l for l in stdout.splitlines() if l.strip()])
    log(f"  Done:    {images[c]} → {outfiles[c]} ({count} packages)")

log(f"RPM queries complete in {time.time() - t1:.1f}s.")


# ── Phase 3: Remove pulled images ────────────────────────────────────────────
log("\nRemoving pulled images...")
cleanup_images(pulled_images)


# ── Write image mapping ───────────────────────────────────────────────────────
with open("cve-data/checked-images.json", "w") as f:
    json.dump(images, f, indent=2)

log(f"\nDone in {time.time() - t0:.1f}s total.")
log(f"  RPM lists: {outfiles[SERVER_CONTAINER]}, {outfiles[UI_CONTAINER]}")
log(f"  Image map: cve-data/checked-images.json")
