#!/usr/bin/env python3
# /// script
# dependencies = []
# ///
"""
Query Red Hat Errata Advisory API for CVE and package build information.

This script queries the internal Red Hat Errata Advisory API to retrieve:
- Advisory metadata (ID, name, synopsis, severity, status)
- CVE IDs extracted from advisory description
- Fixed package builds (Name-Version-Release format) by RHEL release

Requires Kerberos authentication with valid @YOUR_KERBEROS_REALM principal ticket.

All logs and errors go to stderr; only JSON results go to stdout.
"""

import argparse
import json
import re
import subprocess
import sys


def log(message: str) -> None:
    """Log to stderr."""
    print(message, file=sys.stderr)


def check_kerberos_ticket() -> bool:
    """
    Check if user has a valid Kerberos ticket.

    Returns True if valid ticket exists, False otherwise.
    """
    try:
        result = subprocess.run(
            ["klist", "-s"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception as e:
        log(f"WARNING: Could not check Kerberos ticket: {e}")
        return False



def query_advisory(advisory_id: str) -> dict:
    """
    Query Red Hat Errata Advisory API for advisory details.

    Args:
        advisory_id: Advisory ID in any accepted format

    Returns:
        Dict with advisory metadata and extracted CVE IDs from multiple sources
    """
    # Query the full API endpoint to get bugs and jira_issues
    api_url = f"https://[internal-errata-host]/api/v1/erratum/{advisory_id}"
    log(f"Querying advisory API: {api_url}")

    try:
        # Use curl with Kerberos (SPNEGO) authentication
        result = subprocess.run(
            ["curl", "-s", "--negotiate", "-u", ":", api_url],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return {
                "error": "Failed to query advisory API",
                "advisory_id": advisory_id,
                "stderr": result.stderr,
                "url": api_url
            }

        # Parse JSON response
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            # Check if response looks like HTML (authentication failure)
            if result.stdout.strip().startswith("<!DOCTYPE") or result.stdout.strip().startswith("<html"):
                return {
                    "error": "Authentication failed - response is HTML, not JSON. Check Kerberos ticket.",
                    "advisory_id": advisory_id,
                    "url": api_url,
                    "hint": "Run: kinit <username>@YOUR_KERBEROS_REALM"
                }
            return {
                "error": "Failed to parse JSON response",
                "advisory_id": advisory_id,
                "parse_error": str(e),
                "response_preview": result.stdout[:500],
                "url": api_url
            }

        # Extract advisory metadata
        errata_data = data.get("errata", {})
        # The advisory type (rhsa, rhba, rhea) is a key in the errata dict
        advisory_metadata = {}
        for advisory_type in ["rhsa", "rhba", "rhea"]:
            if advisory_type in errata_data:
                advisory_metadata = errata_data[advisory_type]
                break

        # Collect CVE IDs from multiple sources
        all_cve_ids = set()

        # Source 1: Extract CVE IDs from content description
        content = data.get("content", {})
        description = content.get("description", "")
        cve_ids_from_desc = re.findall(r'CVE-\d{4}-\d+', description)
        all_cve_ids.update(cve_ids_from_desc)

        # Source 2: Extract CVE IDs from Bugzilla bugs
        bugs_data = data.get("bugs", {})
        bugs_list = bugs_data.get("bugs", [])
        for bug_entry in bugs_list:
            bug = bug_entry.get("bug", {})
            # Check alias field (often the CVE ID)
            alias = bug.get("alias", "")
            if alias.startswith("CVE-"):
                all_cve_ids.add(alias)
            # Also check short_desc for CVE IDs
            short_desc = bug.get("short_desc", "")
            cve_ids_from_bug = re.findall(r'CVE-\d{4}-\d+', short_desc)
            all_cve_ids.update(cve_ids_from_bug)

        # Source 3: Extract CVE IDs from Jira issues
        jira_data = data.get("jira_issues", {})
        jira_list = jira_data.get("jira_issues", [])
        for jira_entry in jira_list:
            jira_issue = jira_entry.get("jira_issue", {})
            # Check labels for CVE IDs
            labels = jira_issue.get("labels", [])
            for label in labels:
                if label.startswith("CVE-"):
                    all_cve_ids.add(label)
            # Also check summary for CVE IDs
            summary = jira_issue.get("summary", "")
            cve_ids_from_jira = re.findall(r'CVE-\d{4}-\d+', summary)
            all_cve_ids.update(cve_ids_from_jira)

        return {
            "advisory_id": advisory_metadata.get("id"),
            "advisory_name": advisory_metadata.get("old_advisory") or advisory_metadata.get("fulladvisory", ""),
            "synopsis": advisory_metadata.get("synopsis"),
            "security_impact": advisory_metadata.get("security_impact"),
            "status": advisory_metadata.get("status"),
            "cve_ids": sorted(all_cve_ids),  # Deduplicate and sort
            "url": api_url
        }

    except subprocess.TimeoutExpired:
        return {
            "error": "Request timeout",
            "advisory_id": advisory_id,
            "url": api_url
        }
    except Exception as e:
        return {
            "error": str(e),
            "advisory_id": advisory_id,
            "url": api_url
        }


def query_advisory_builds(advisory_id: str) -> dict:
    """
    Query Red Hat Errata Advisory API for fixed package builds.

    Args:
        advisory_id: Advisory ID in any accepted format

    Returns:
        Dict with builds organized by RHEL release
    """
    url = f"https://[internal-errata-host]/api/v1/erratum/{advisory_id}/builds"
    log(f"Querying builds API: {url}")

    try:
        # Use curl with Kerberos (SPNEGO) authentication
        result = subprocess.run(
            ["curl", "-s", "--negotiate", "-u", ":", url],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return {
                "error": "Failed to query builds API",
                "stderr": result.stderr,
                "url": url
            }

        # Parse JSON response
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            # Check if response looks like HTML (authentication failure)
            if result.stdout.strip().startswith("<!DOCTYPE") or result.stdout.strip().startswith("<html"):
                return {
                    "error": "Authentication failed - response is HTML, not JSON. Check Kerberos ticket.",
                    "url": url,
                    "hint": "Run: kinit <username>@YOUR_KERBEROS_REALM"
                }
            return {
                "error": "Failed to parse JSON response",
                "parse_error": str(e),
                "response_preview": result.stdout[:500],
                "url": url
            }

        # Extract builds from nested structure
        # Structure: {release_key: {name: str, builds: [{nvr: {...}}, ...]}}
        builds_by_release = {}

        for release_key, release_data in data.items():
            if "builds" in release_data and release_data["builds"]:
                # Process each build in this release
                builds_list = []

                for build_entry in release_data["builds"]:
                    # Each build_entry is a dict with package NVR as key
                    for nvr, build_details in build_entry.items():
                        # Collect all RPMs from all variants and architectures
                        rpms_by_arch = {}

                        variant_arch_data = build_details.get("variant_arch", {})
                        for variant_name, arch_data in variant_arch_data.items():
                            for arch, rpm_list in arch_data.items():
                                if arch not in rpms_by_arch:
                                    rpms_by_arch[arch] = []
                                rpms_by_arch[arch].extend(rpm_list)

                        # Sort and deduplicate RPMs per architecture
                        for arch in rpms_by_arch:
                            rpms_by_arch[arch] = sorted(set(rpms_by_arch[arch]))

                        # Parse NEVR (Name-Epoch:Version-Release) to extract components
                        # Format: "python3.9-0:3.9.25-5.el9_8" or "openssh-9.9p1-7.el9_8" (no epoch)
                        nevr = build_details.get("nevr", "")
                        name = ""
                        epoch = ""
                        version = ""
                        release = ""

                        if nevr:
                            # Split on colon to separate epoch
                            if ":" in nevr:
                                name_epoch, version_release = nevr.rsplit(":", 1)
                                # Further split to get name and epoch
                                name, epoch = name_epoch.rsplit("-", 1)
                            else:
                                # No epoch present
                                name_epoch = nevr
                                version_release = ""

                            # Split version-release on last hyphen
                            if version_release:
                                parts = version_release.rsplit("-", 1)
                                if len(parts) == 2:
                                    version, release = parts
                            elif "-" in nevr and ":" not in nevr:
                                # Handle case with no epoch in nevr format
                                # Try to parse from NVR instead
                                nvr_parts = nvr.rsplit("-", 2)
                                if len(nvr_parts) == 3:
                                    name, version, release = nvr_parts

                        if nevr and not (name and version and release):
                            log(f"WARNING: NEVR parsing incomplete for '{nevr}' "
                                f"(name={name!r}, version={version!r}, release={release!r}). "
                                f"NVR field will be present but components may be empty.")

                        builds_list.append({
                            "nvr": nvr,
                            "name": name,
                            "epoch": epoch if epoch else None,
                            "version": version,
                            "release": release,
                            "build_id": build_details.get("id"),
                            "rpms_by_arch": rpms_by_arch
                        })

                if builds_list:
                    builds_by_release[release_key] = {
                        "release_name": release_data.get("name", release_key),
                        "builds": builds_list
                    }

        return {
            "releases": builds_by_release
        }

    except subprocess.TimeoutExpired:
        return {
            "error": "Request timeout",
            "url": url
        }
    except Exception as e:
        return {
            "error": str(e),
            "url": url
        }


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Query Red Hat Errata Advisory API for CVE and package build information.",
        epilog="""
AUTHENTICATION:
  Requires valid Kerberos ticket for @YOUR_KERBEROS_REALM principal.

  To authenticate:
    kinit <username>@YOUR_KERBEROS_REALM

  To check ticket status:
    klist -s

  This script will check for a valid ticket before querying the API.

ADVISORY ID FORMATS:
  The Errata API accepts multiple advisory ID formats:
    - Numeric ID: '165765'
    - Simple RHSA: 'RHSA-165765'
    - Full RHSA: 'RHSA-2026:6923' (with year)

  All formats work directly with the API.

OUTPUT FORMAT:
  JSON object containing:
    - input_advisory_id: The advisory ID you provided
    - advisory_id: Numeric ID from API response
    - advisory_name: Full RHSA designation (e.g., "RHSA-2026:6923")
    - synopsis: Advisory synopsis text
    - security_impact: Severity level ("Important", "Moderate", "Low", "Critical")
    - status: Advisory status
    - cve_ids: Sorted unique list of CVE IDs (extracted from description, Bugzilla bugs, and Jira issues)
    - releases: Dict of RHEL releases, each containing:
        - release_name: Human-readable release name
        - builds: List of build objects, each with:
            - nvr: Package Name-Version-Release (full string)
            - name: Package name (e.g., "python3.9")
            - epoch: Package epoch (null if not present)
            - version: Package version (e.g., "3.9.25")
            - release: Package release (e.g., "5.el9_8")
            - build_id: Brew build ID (for brewweb links)
            - rpms_by_arch: Dict of RPM lists grouped by architecture

  Example output:
    {
      "input_advisory_id": "165721",
      "advisory_id": 165721,
      "advisory_name": "RHSA-2026:6923",
      "synopsis": "Important: openssh security update",
      "security_impact": "Important",
      "status": "SHIPPED_LIVE",
      "cve_ids": ["CVE-2026-12345", "CVE-2026-67890"],
      "releases": {
        "RHEL-9.8.0.GA": {
          "release_name": "RHEL-9.8.0.GA",
          "builds": [
            {
              "nvr": "openssh-9.9p1-7.el9_8",
              "name": "openssh",
              "epoch": null,
              "version": "9.9p1",
              "release": "7.el9_8",
              "build_id": 3970341,
              "rpms_by_arch": {
                "x86_64": ["openssh-9.9p1-7.el9_8.x86_64.rpm", ...],
                "aarch64": ["openssh-9.9p1-7.el9_8.aarch64.rpm", ...],
                "noarch": ["openssh-common-9.9p1-7.el9_8.noarch.rpm"]
              }
            }
          ]
        }
      }
    }

EXAMPLES:
  # Query advisory with numeric ID
  %(prog)s 165721

  # Query advisory with RHSA designation
  %(prog)s RHSA-165721

  # Query and extract only CVE IDs
  %(prog)s 165721 | jq -r '.cve_ids[]'

  # Extract package NVRs for specific release
  %(prog)s 165721 | jq -r '.releases["RHEL-9.8.0.GA"].builds[].nvr'

  # Extract all x86_64 RPMs across all releases
  %(prog)s 165721 | jq -r '.releases[].builds[].rpms_by_arch.x86_64[]?'

  # Get Brew build IDs and URLs
  %(prog)s 165721 | jq -r '.releases[].builds[] | "https://[internal-brew-host]/brew/buildinfo?buildID=\(.build_id)"'

  # Query from parse-prograde-advisories.py output
  parse-prograde-advisories.py emails.json | jq -r '.advisories[].advisory_id' | while read id; do %(prog)s "$id"; done

CVE EXTRACTION:
  CVE IDs are extracted from multiple sources to ensure completeness:
    1. Advisory description field (primary source)
    2. Linked Bugzilla bugs (alias and description fields)
    3. Linked Jira issues (labels and summary fields)

  Some advisories may show only 1 CVE in the description but fix additional CVEs
  tracked in separate Bugzilla or Jira issues. This script aggregates all CVEs
  from all sources.

INTEGRATION:
  This script extracts the specific package builds (Name-Version-Release) that
  resolved CVEs in an advisory. The NVR strings can be:
    1. Compared against installed versions in containers/systems
    2. Used to identify which packages need updating
    3. Cross-referenced with CVE tracking systems (JIRA, Red Hat Catalog)

NOTE:
  All logs and error messages go to stderr.
  Only JSON output goes to stdout.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        'advisory_id',
        metavar='ADVISORY_ID',
        help='Red Hat advisory ID (e.g., "165765", "RHSA-165765", or "RHSA-2026:6923")',
    )

    args = parser.parse_args()

    # Check for Kerberos ticket
    if not check_kerberos_ticket():
        log("WARNING: No valid Kerberos ticket found.")
        log("         Run: kinit <username>@YOUR_KERBEROS_REALM")
        log("         Continuing anyway - API may return authentication error.")
        log("")

    # Normalize advisory ID
    advisory_id = args.advisory_id.strip()

    # Query advisory details
    advisory_data = query_advisory(advisory_id)

    if "error" in advisory_data:
        log(f"ERROR: {advisory_data['error']}")
        if "hint" in advisory_data:
            log(f"HINT: {advisory_data['hint']}")
        # Still output JSON with error for downstream processing
        print(json.dumps(advisory_data, indent=2))
        sys.exit(1)

    # Query builds
    builds_data = query_advisory_builds(advisory_id)

    if "error" in builds_data:
        log(f"WARNING: Failed to query builds: {builds_data['error']}")
        # Include partial data with error noted
        result = {
            **advisory_data,
            "input_advisory_id": args.advisory_id,
            "releases": {},
            "builds_error": builds_data["error"]
        }
    else:
        # Combine results
        result = {
            "input_advisory_id": args.advisory_id,
            "advisory_id": advisory_data["advisory_id"],
            "advisory_name": advisory_data["advisory_name"],
            "synopsis": advisory_data["synopsis"],
            "security_impact": advisory_data["security_impact"],
            "status": advisory_data["status"],
            "cve_ids": advisory_data["cve_ids"],
            "releases": builds_data["releases"]
        }

    # Output JSON to stdout (only this goes to stdout!)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
