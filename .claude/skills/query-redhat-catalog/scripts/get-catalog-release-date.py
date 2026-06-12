#!/usr/bin/env python3
# /// script
# dependencies = [
#     "httpx>=0.27.0",
# ]
# ///
"""
Get the publication date of the latest Discovery container images from the Red Hat Catalog.

Queries the catalog image detail API for both discovery-server and discovery-ui,
extracts the creation_date of the current 'latest' image, and outputs the earlier
of the two dates (so queries using this date are inclusive of the full release).

Output: a single ISO date string (YYYY-MM-DD) to stdout.
All logs go to stderr.
"""

import argparse
import sys

import httpx

CATALOG_BASE = "https://catalog.redhat.com"

CONTAINER_REPO_IDS = {
    "discovery-server": "64cabaaca7460ea2e782ac6e",
    "discovery-ui": "66fd8f5c7f6fd21630e914d9",
}


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def get_image_creation_date(repo_id: str, tag: str = "latest", arch: str = "amd64") -> str | None:
    """Return the creation_date (ISO string) of the current image for a given tag."""
    url = f"{CATALOG_BASE}/api/containers/v1/repositories/id/{repo_id}"
    try:
        resp = httpx.get(url, timeout=30.0)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        log(f"ERROR: Failed to fetch repo {repo_id}: {e}")
        return None

    image_id = None
    for entry in data.get("content_stream_grades", []):
        if entry.get("tag") == tag:
            for img in entry.get("image_ids", []):
                if img.get("arch") == arch:
                    image_id = img.get("id")
                    break
            if not image_id:
                images = entry.get("image_ids", [])
                if images:
                    image_id = images[0].get("id")
            break

    if not image_id:
        log(f"ERROR: Could not find image ID for tag='{tag}' arch='{arch}' in repo {repo_id}")
        return None

    img_url = f"{CATALOG_BASE}/api/containers/v1/images/id/{image_id}"
    try:
        ir = httpx.get(img_url, timeout=30.0)
        ir.raise_for_status()
        idata = ir.json()
    except Exception as e:
        log(f"ERROR: Failed to fetch image {image_id}: {e}")
        return None

    return idata.get("creation_date")


def main():
    parser = argparse.ArgumentParser(
        description="Get the publication date of the latest Discovery downstream images."
    )
    parser.add_argument(
        "--tag",
        default="latest",
        help='Image tag to check (default: "latest")',
    )
    parser.add_argument(
        "--arch",
        default="amd64",
        help='Image architecture (default: "amd64")',
    )
    args = parser.parse_args()

    dates = {}
    for container, repo_id in CONTAINER_REPO_IDS.items():
        log(f"Fetching release date for {container}:{args.tag}...")
        raw = get_image_creation_date(repo_id, tag=args.tag, arch=args.arch)
        if not raw:
            log(f"ERROR: Could not determine release date for {container}")
            sys.exit(1)
        date_only = raw[:10]  # "YYYY-MM-DD" from ISO timestamp
        log(f"  {container}: {date_only}")
        dates[container] = date_only

    release_date = min(dates.values())
    log(f"Earliest release date: {release_date}")
    print(release_date)


if __name__ == "__main__":
    main()
