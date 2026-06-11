#!/usr/bin/env python3
"""Pull container images and query all installed RPM packages.

Pulls discovery-server and discovery-ui images in parallel, queries all
installed RPMs from each container in a single run per image, writes the
results to cve-data/, then removes the images.

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


# ── Phase 1: Pull both images in parallel ────────────────────────────────────
print("Pulling container images in parallel...", flush=True)
t0 = time.time()

pull_tasks = [(c, ["podman", "pull", img]) for c, img in images.items()]
for c, _ in pull_tasks:
    print(f"  Starting pull: {images[c]}", flush=True)

pull_results = wait_procs(start_procs(pull_tasks))

failed = [c for c, (rc, _, _) in pull_results.items() if rc != 0]
if failed:
    for c in failed:
        _, _, stderr = pull_results[c]
        print(f"  FAILED: {images[c]}\n    {stderr.strip()}", file=sys.stderr)
    sys.exit(1)

for c in images:
    print(f"  Pulled:  {images[c]}", flush=True)
print(f"All images pulled in {time.time() - t0:.1f}s.", flush=True)


# ── Phase 2: Query RPMs from both containers in parallel ─────────────────────
print("\nQuerying installed RPMs in parallel...", flush=True)
t1 = time.time()

rpm_tasks = [
    (c, ["podman", "run", "--rm", img, "bash", "-c", "rpm -qa | sort"])
    for c, img in images.items()
]
for c, _ in rpm_tasks:
    print(f"  Starting rpm -qa: {images[c]}", flush=True)

rpm_results = wait_procs(start_procs(rpm_tasks))

failed = [c for c, (rc, _, _) in rpm_results.items() if rc != 0]
if failed:
    for c in failed:
        _, _, stderr = rpm_results[c]
        print(f"  FAILED: {images[c]}\n    {stderr.strip()}", file=sys.stderr)
    # Clean up pulled images before exiting
    for img in images.values():
        subprocess.run(["podman", "rmi", img], capture_output=True)
    sys.exit(1)

for c, (_, stdout, _) in rpm_results.items():
    with open(outfiles[c], "w") as f:
        f.write(stdout)
    count = len([l for l in stdout.splitlines() if l.strip()])
    print(f"  Done:    {images[c]} → {outfiles[c]} ({count} packages)", flush=True)

print(f"RPM queries complete in {time.time() - t1:.1f}s.", flush=True)


# ── Phase 3: Remove pulled images ────────────────────────────────────────────
print("\nRemoving pulled images...", flush=True)
for c, img in images.items():
    subprocess.run(["podman", "rmi", img], capture_output=True)
    print(f"  Removed: {img}", flush=True)


# ── Write image mapping ───────────────────────────────────────────────────────
with open("cve-data/checked-images.json", "w") as f:
    json.dump(images, f, indent=2)

print(f"\nDone in {time.time() - t0:.1f}s total.")
print(f"  RPM lists: {outfiles[SERVER_CONTAINER]}, {outfiles[UI_CONTAINER]}")
print(f"  Image map: cve-data/checked-images.json")
