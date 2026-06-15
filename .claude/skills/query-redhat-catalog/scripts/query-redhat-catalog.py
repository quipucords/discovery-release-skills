#!/usr/bin/env python3
# /// script
# dependencies = [
#     "httpx>=0.27.0",
# ]
# ///
"""
Query CVE vulnerability data from the Red Hat Container Catalog for Discovery containers.

Uses the catalog's internal GraphQL API to retrieve vulnerability data directly —
no browser automation required. Two API calls per container:
  1. REST: look up image ID(s) for the requested tag
  2. GraphQL: query vulnerabilities for that image ID

All logs and errors go to stderr; only JSON results go to stdout.
"""

import argparse
import json
import os
import sys

import httpx


CATALOG_BASE = "https://catalog.redhat.com"
GRAPHQL_URL = f"{CATALOG_BASE}/api/containers/graphql/"

# Container short names (used as dict keys and --container arg values).
_SERVER_NAME = os.environ.get("CATALOG_SERVER_NAME", "discovery-server")
_UI_NAME     = os.environ.get("CATALOG_UI_NAME",     "discovery-ui")

# Downstream image base URLs (strip the registry host to get the image-name path).
_DOWNSTREAM_SERVER_IMAGE = os.environ.get("DOWNSTREAM_SERVER_IMAGE", "registry.redhat.io/discovery/discovery-server-rhel9")
_DOWNSTREAM_UI_IMAGE     = os.environ.get("DOWNSTREAM_UI_IMAGE",     "registry.redhat.io/discovery/discovery-ui-rhel9")

# Repository IDs from the catalog page URLs (stable, set via CATALOG_SERVER_ID / CATALOG_UI_ID).
CONTAINER_REPO_IDS = {
    _SERVER_NAME: os.environ.get("CATALOG_SERVER_ID", "64cabaaca7460ea2e782ac6e"),
    _UI_NAME:     os.environ.get("CATALOG_UI_ID",     "66fd8f5c7f6fd21630e914d9"),
}

CONTAINER_IMAGE_NAMES = {
    _SERVER_NAME: _DOWNSTREAM_SERVER_IMAGE.split("/", 1)[1],
    _UI_NAME:     _DOWNSTREAM_UI_IMAGE.split("/", 1)[1],
}

# GraphQL query for vulnerabilities - mirrors the catalog page's FIND_IMAGE_VULNERABILITIES
VULN_QUERY = """
query FIND_IMAGE_VULNERABILITIES($id: String, $page: Int, $pageSize: Int) {
  ContainerImageVulnerability: find_image_vulnerabilities(
    id: $id
    page: $page
    page_size: $pageSize
  ) {
    data {
      _id
      creation_date
      advisory_id
      advisory_type
      cve_id
      severity
      affected_packages {
        name
        version
        arch
        package_type
      }
      packages {
        rpm_nvra
      }
    }
  }
}
"""


def log(message: str) -> None:
    print(message, file=sys.stderr)


def get_image_id(repo_id: str, tag: str = "latest", arch: str = "amd64") -> str | None:
    """
    Look up the internal image ID for a specific tag and arch from the repository metadata.

    The catalog REST API returns content_stream_grades which maps tags to image IDs.
    We use amd64 by default since vulnerability data is arch-agnostic at the CVE level.
    """
    url = f"{CATALOG_BASE}/api/containers/v1/repositories/id/{repo_id}"
    try:
        response = httpx.get(url, timeout=30.0)
        response.raise_for_status()
        data = response.json()

        # content_stream_grades is a list of {grade, tag, image_ids: [{arch, id}]}
        for entry in data.get("content_stream_grades", []):
            if entry.get("tag") == tag:
                for image in entry.get("image_ids", []):
                    if image.get("arch") == arch:
                        return image.get("id")

        # Fall back to first available image ID for the tag if arch not found
        for entry in data.get("content_stream_grades", []):
            if entry.get("tag") == tag:
                images = entry.get("image_ids", [])
                if images:
                    fallback_arch = images[0].get("arch")
                    log(f"WARNING: arch '{arch}' not found for tag '{tag}', using '{fallback_arch}'")
                    return images[0].get("id")

        return None

    except httpx.HTTPStatusError as e:
        log(f"ERROR: Failed to look up repository {repo_id}: HTTP {e.response.status_code}")
        return None
    except Exception as e:
        log(f"ERROR: Failed to look up repository {repo_id}: {e}")
        return None


def query_vulnerabilities(image_id: str, page_size: int = 250) -> list[dict]:
    """
    Query the catalog GraphQL API for all vulnerabilities in a specific image.

    Uses pagination to retrieve all results even if they exceed a single page.
    """
    all_vulns = []
    page = 0

    while True:
        try:
            response = httpx.post(
                GRAPHQL_URL,
                json={
                    "operationName": "FIND_IMAGE_VULNERABILITIES",
                    "variables": {
                        "id": image_id,
                        "page": page,
                        "pageSize": page_size,
                    },
                    "query": VULN_QUERY,
                },
                headers={"content-type": "application/json"},
                timeout=30.0,
            )
            response.raise_for_status()
            data = response.json()

            vulns = (
                data.get("data", {})
                .get("ContainerImageVulnerability", {})
                .get("data", [])
            )

            if not vulns:
                break

            all_vulns.extend(vulns)

            # If we got a full page, there may be more
            if len(vulns) < page_size:
                break

            page += 1

        except httpx.HTTPStatusError as e:
            log(f"ERROR: GraphQL request failed: HTTP {e.response.status_code}")
            break
        except Exception as e:
            log(f"ERROR: GraphQL request failed: {e}")
            break

    return all_vulns


def format_cve(raw: dict, container_key: str) -> dict:
    """Format a raw GraphQL vulnerability record into our output schema."""
    advisory_type = raw.get("advisory_type", "RHSA")
    advisory_id_short = raw.get("advisory_id", "")
    # advisory_id from API is "2026:12441"; full form is "RHSA-2026:12441"
    advisory_full = f"{advisory_type}-{advisory_id_short}" if advisory_id_short else None
    advisory_link = (
        f"https://access.redhat.com/errata/{advisory_full}" if advisory_full else None
    )

    cve_id = raw.get("cve_id")
    cve_link = (
        f"https://access.redhat.com/security/cve/{cve_id}" if cve_id else None
    )

    # rpm_nvra is a list of lists (one list of NVRAs per package group)
    rpm_nvras = []
    for pkg_group in raw.get("packages", []):
        rpm_nvras.extend(pkg_group.get("rpm_nvra", []))

    return {
        "container": container_key,
        "image_name": CONTAINER_IMAGE_NAMES[container_key],
        "cve_id": cve_id,
        "cve_link": cve_link,
        "severity": raw.get("severity"),
        "advisory_id": advisory_full,
        "advisory_link": advisory_link,
        "creation_date": raw.get("creation_date"),
        "affected_packages": raw.get("affected_packages", []),
        "rpm_nvras": rpm_nvras,
    }


def query_container(container_key: str, tag: str, arch: str) -> list[dict]:
    """Look up image ID and retrieve all CVEs for one container."""
    repo_id = CONTAINER_REPO_IDS[container_key]
    image_name = CONTAINER_IMAGE_NAMES[container_key]

    log(f"Looking up image ID for {image_name}:{tag} ({arch})")
    image_id = get_image_id(repo_id, tag=tag, arch=arch)

    if not image_id:
        log(f"ERROR: Could not find image ID for {image_name} tag='{tag}' arch='{arch}'")
        return []

    log(f"Found image ID: {image_id}")
    log(f"Querying vulnerabilities for {image_name}")

    raw_vulns = query_vulnerabilities(image_id)
    log(f"Found {len(raw_vulns)} CVEs for {image_name}")

    return [format_cve(v, container_key) for v in raw_vulns]


def main():
    parser = argparse.ArgumentParser(
        description="Query CVE vulnerability data from the Red Hat Container Catalog.",
        epilog="""
DATA SOURCE:
  Uses the Red Hat Container Catalog's GraphQL API at catalog.redhat.com.
  No authentication required — public data. No browser needed.

  Two API calls per container:
    1. REST  GET /api/containers/v1/repositories/id/{repo_id}
             Resolves the tag (e.g., "latest") to an internal image ID.
    2. GraphQL POST /api/containers/graphql/
             FIND_IMAGE_VULNERABILITIES query returns all CVEs for that image.

  Container repository IDs (stable, from catalog page URLs):
    discovery-server: 64cabaaca7460ea2e782ac6e
    discovery-ui:     66fd8f5c7f6fd21630e914d9

IMPORTANT — published downstream image only:
  Vulnerability data reflects the PUBLISHED DOWNSTREAM image
  (registry.redhat.io/discovery/...), not the upstream Quay.io image.
  A new upstream release will not appear here until it is published downstream.

OUTPUT FORMAT:
  JSON object with:
    - total: Total CVE count across all queried containers
    - cves: Array of CVE objects, each containing:
        - container:          Short key ("discovery-server" or "discovery-ui")
        - image_name:         Full image name ("discovery/discovery-server-rhel9")
        - cve_id:             CVE identifier (e.g., "CVE-2026-4878")
        - cve_link:           URL to Red Hat CVE detail page
        - severity:           "Critical", "Important", "Moderate", or "Low"
        - advisory_id:        Full RHSA designation (e.g., "RHSA-2026:12441")
        - advisory_link:      URL to the RHSA advisory page
        - creation_date:      ISO 8601 timestamp when the CVE entry was created
        - affected_packages:  List of {name, version, arch, package_type} dicts
        - rpm_nvras:          List of full RPM NVRA strings (e.g., "gnutls-3.8.10-3.el9.x86_64")

  Example:
    {
      "total": 2,
      "cves": [
        {
          "container": "discovery-server",
          "image_name": "discovery/discovery-server-rhel9",
          "cve_id": "CVE-2026-4878",
          "cve_link": "https://access.redhat.com/security/cve/CVE-2026-4878",
          "severity": "Important",
          "advisory_id": "RHSA-2026:12441",
          "advisory_link": "https://access.redhat.com/errata/RHSA-2026:12441",
          "creation_date": "2026-05-21T22:07:38.474000+00:00",
          "affected_packages": [
            {"name": "libcap", "version": "2.48-10.el9", "arch": "x86_64", "package_type": "rpm"}
          ],
          "rpm_nvras": ["libcap-2.48-10.el9.x86_64"]
        }
      ]
    }

INTEGRATION:
  - advisory_id can be passed to query-errata-advisory.py for fixed package NVRs
  - cve_id can be cross-referenced with query-jira-cves.py and parse-prograde-advisories.py
  - rpm_nvras shows currently installed vulnerable versions (useful for comparison)

EXAMPLES:
  # Query both containers (default)
  %(prog)s

  # Query only the server container
  %(prog)s --container discovery-server

  # Query a specific published version tag
  %(prog)s --tag 2.5.1

  # Extract only Important or Critical CVEs
  %(prog)s | jq '.cves[] | select(.severity == "Important" or .severity == "Critical")'

  # Get unique advisory IDs for query-errata-advisory.py
  %(prog)s | jq -r '.cves[].advisory_id | select(. != null)' | sort -u

  # Get all CVE IDs as a flat list
  %(prog)s | jq -r '.cves[].cve_id' | sort -u

NOTE:
  All logs and error messages go to stderr.
  Only JSON output goes to stdout.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--container",
        choices=[*CONTAINER_REPO_IDS.keys(), "all"],
        default="all",
        help='Container to query: {}, or "all" (default: all)'.format(", ".join(f'"{k}"' for k in CONTAINER_REPO_IDS)),
    )
    parser.add_argument(
        "--tag",
        default="latest",
        metavar="TAG",
        help='Published image tag to query (default: "latest")',
    )
    parser.add_argument(
        "--arch",
        default="amd64",
        metavar="ARCH",
        help='Image architecture for tag lookup (default: "amd64")',
    )

    args = parser.parse_args()

    containers = (
        list(CONTAINER_REPO_IDS.keys()) if args.container == "all" else [args.container]
    )

    all_cves = []
    for container_key in containers:
        cves = query_container(container_key, tag=args.tag, arch=args.arch)
        all_cves.extend(cves)

    print(json.dumps({"total": len(all_cves), "cves": all_cves}, indent=2))


if __name__ == "__main__":
    main()
