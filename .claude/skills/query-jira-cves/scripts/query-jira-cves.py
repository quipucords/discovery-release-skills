#!/usr/bin/env python3
# /// script
# dependencies = [
#     "httpx>=0.27.0",
# ]
# ///
"""
Query JIRA for CVE-related security issues.

This script searches JIRA for security issues (typically with Security label)
and extracts CVE information for tracking and remediation.

All logs and errors go to stderr; only JSON results go to stdout.
"""

import argparse
import json
import os
import re
import sys

import httpx

_JIRA_PROJECT = os.environ.get("JIRA_PROJECT", "DISCOVERY")
_JIRA_NVR_PATTERN = os.environ.get(
    "JIRA_NVR_PATTERN",
    r'(?:discovery/discovery-\w+-rhel\d+|redhat-user-workloads/discovery-\w+):\s+(.+)',
)


def log(message: str) -> None:
    """Log to stderr."""
    print(message, file=sys.stderr)


def get_jira_credentials() -> tuple[str, str, str]:
    """
    Get JIRA credentials from environment variables.

    Returns:
        Tuple of (jira_host, email, api_token)

    Raises:
        ValueError: If required credentials are missing
    """
    jira_host = os.getenv("JIRA_HOST", "redhat.atlassian.net")
    jira_email = os.getenv("JIRA_EMAIL")
    jira_api_token = os.getenv("JIRA_API_TOKEN")

    if not jira_email or not jira_api_token:
        raise ValueError(
            "JIRA credentials not configured. Please set JIRA_EMAIL and JIRA_API_TOKEN environment variables."
        )

    return jira_host, jira_email, jira_api_token


def search_jira_issues(
    jira_host: str,
    email: str,
    api_token: str,
    project: str = _JIRA_PROJECT,
    label: str | None = None,
    summary_contains: str | None = None,
    created_since: str | None = None,
    status_in: list[str] | None = None,
    status_not_in: list[str] | None = None,
    max_results: int = 100,
) -> dict:
    """
    Search for issues in JIRA using JQL.

    Args:
        jira_host: JIRA instance hostname
        email: JIRA user email
        api_token: JIRA API token
        project: Project key to search (default: $JIRA_PROJECT or "DISCOVERY")
        label: Label to filter by (optional)
        summary_contains: Text to search in issue summary/title (optional)
        created_since: Only return issues created on or after this date (YYYY-MM-DD)
        status_in: List of statuses to include (mutually exclusive with status_not_in)
        status_not_in: List of statuses to exclude (default: ["Done", "Closed"])
        max_results: Maximum number of results to return

    Returns:
        Dict with search results and metadata
    """
    # Build JQL query
    jql_parts = []

    if project:
        jql_parts.append(f"project = {project}")

    if label:
        jql_parts.append(f"labels = {label}")

    if summary_contains:
        # Search in summary field with wildcard
        # The ~ operator with quotes and * wildcard matches text containing the term
        jql_parts.append(f"summary ~ \"{summary_contains}*\"")

    if created_since:
        # JQL date format is "YYYY-MM-DD"
        jql_parts.append(f"created >= \"{created_since}\"")

    # Add status filter (status_in takes precedence)
    # Quote status names that contain spaces or special characters
    if status_in:
        quoted_statuses = [f'"{s}"' if ' ' in s else s for s in status_in]
        status_list = ", ".join(quoted_statuses)
        jql_parts.append(f"status IN ({status_list})")
    elif status_not_in:
        quoted_statuses = [f'"{s}"' if ' ' in s else s for s in status_not_in]
        status_list = ", ".join(quoted_statuses)
        jql_parts.append(f"status NOT IN ({status_list})")

    jql = " AND ".join(jql_parts) if jql_parts else ""

    # Add ordering by due date (ascending - oldest first), then by updated date
    # This is important when limiting results to ensure we see the most urgent issues first
    # Secondary sort by updated ensures consistent ordering for issues with same/no due date
    jql += " ORDER BY due ASC, updated ASC"

    log(f"JQL Query: {jql}")

    # Prepare API request
    url = f"https://{jira_host}/rest/api/3/search/jql"
    params = {
        "jql": jql,
        "maxResults": max_results,
        "fields": "summary,status,labels,created,updated,duedate,description,issuelinks,assignee,reporter,customfield_10669,customfield_*"
    }

    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.get(
                url,
                params=params,
                auth=(email, api_token)
            )
            response.raise_for_status()
            data = response.json()

            # Extract relevant information
            issues = []
            raw_issues = data.get("issues", [])
            log(f"Found {len(raw_issues)} issues")

            for issue in raw_issues:
                fields = issue.get("fields", {})

                # Extract CVE IDs from labels (labels that start with CVE-)
                cve_labels = [
                    label for label in fields.get("labels", [])
                    if label.startswith("CVE-")
                ]

                # Also extract CVE IDs from summary and description using regex
                summary = fields.get("summary", "")
                description_obj = fields.get("description")

                # JIRA description can be in different formats (string or Atlassian Document Format)
                description_text = ""
                if isinstance(description_obj, str):
                    description_text = description_obj
                elif isinstance(description_obj, dict):
                    # Atlassian Document Format - extract text content
                    description_text = extract_text_from_adf(description_obj)

                # Find CVE IDs in text fields
                cve_from_summary = re.findall(r'CVE-\d{4}-\d+', summary)
                cve_from_description = re.findall(r'CVE-\d{4}-\d+', description_text)

                # Combine all CVE sources and deduplicate
                all_cves = set(cve_labels + cve_from_summary + cve_from_description)

                # Extract vulnerable package NVRs from description.
                # These appear in an "AI_ONLY_REPORT" block (a newer convention) as:
                #   "package: python-pip-26.0.1-2.1.hum1"
                # IMPORTANT: this is the VULNERABLE version, NOT the fixed version.
                # The description confirms with fields like "Version affected: 26.0.1"
                # and "Version fixed (if any already): unknown".
                # Older issues do not have this structured block at all.
                vulnerable_package_nvrs = re.findall(r'AI_ONLY_REPORT\s+package:\s*(\S+)', description_text)

                # Extract package name from summary.
                # The most common format after the container name prefix is:
                #   "PackageName: Description [discovery-2]"
                # This is an upstream package name (e.g., "Axios", "urllib3", "Django"),
                # not an RPM name. Issues without a colon-separated prefix return None.
                package_name = None
                summary_tail_match = re.search(_JIRA_NVR_PATTERN, summary)
                if summary_tail_match:
                    tail = summary_tail_match.group(1)
                    colon_match = re.match(r'^([^:]{2,40}):\s+\S', tail)
                    if colon_match:
                        package_name = colon_match.group(1).strip()

                # Extract upstream fixed versions from description prose.
                # These appear as e.g. "fixed in 1.15.1" or "patched in version 11.1.0".
                # IMPORTANT: these are UPSTREAM package versions (semver), NOT RPM NVRs.
                # Use Errata/Prograde data to find the corresponding fixed RPM NVRs.
                upstream_fixed_versions = re.findall(
                    r'(?:fixed in|patched in)\s+(?:version\s+)?([\d][.\d\w]+)',
                    description_text,
                    re.IGNORECASE
                )

                # Extract affected container from customfield_10669 ("Downstream Component Name").
                # This field is consistently populated across all issue generations and covers
                # both naming conventions seen in practice:
                #   "discovery/discovery-server-rhel9"
                #   "redhat-user-workloads/discovery-server"
                downstream_component = fields.get("customfield_10669")


                # Extract custom fields
                custom_fields = {}
                for key, value in fields.items():
                    if key.startswith("customfield_") and value is not None:
                        # For common custom fields, use more readable names
                        if isinstance(value, dict) and "value" in value:
                            custom_fields[key] = value["value"]
                        elif isinstance(value, list) and len(value) > 0:
                            if isinstance(value[0], dict) and "value" in value[0]:
                                custom_fields[key] = [item["value"] for item in value]
                            else:
                                custom_fields[key] = value
                        else:
                            custom_fields[key] = value

                # Extract linked issues (including parent/child relationships)
                linked_issues = []
                for link in fields.get("issuelinks", []):
                    if "outwardIssue" in link:
                        linked_issue = link["outwardIssue"]
                        linked_issues.append({
                            "key": linked_issue.get("key"),
                            "summary": linked_issue.get("fields", {}).get("summary"),
                            "status": linked_issue.get("fields", {}).get("status", {}).get("name"),
                            "link_type": link.get("type", {}).get("outward", "links to")
                        })
                    elif "inwardIssue" in link:
                        linked_issue = link["inwardIssue"]
                        linked_issues.append({
                            "key": linked_issue.get("key"),
                            "summary": linked_issue.get("fields", {}).get("summary"),
                            "status": linked_issue.get("fields", {}).get("status", {}).get("name"),
                            "link_type": link.get("type", {}).get("inward", "linked from")
                        })

                issue_data = {
                    "key": issue.get("key"),
                    "summary": summary,
                    "description": description_text,
                    "status": fields.get("status", {}).get("name"),
                    "labels": fields.get("labels", []),
                    "cve_ids": sorted(all_cves),
                    "package_name": package_name,
                    "vulnerable_package_nvrs": vulnerable_package_nvrs,
                    "upstream_fixed_versions": upstream_fixed_versions,
                    "downstream_component": downstream_component,
                    "created": fields.get("created"),
                    "updated": fields.get("updated"),
                    "duedate": fields.get("duedate"),  # May be null if not set
                    "assignee": fields.get("assignee", {}).get("displayName") if fields.get("assignee") else None,
                    "reporter": fields.get("reporter", {}).get("displayName") if fields.get("reporter") else None,
                    "linked_issues": linked_issues,
                    "custom_fields": custom_fields,
                    "url": f"https://{jira_host}/browse/{issue.get('key')}"
                }
                issues.append(issue_data)

            return {
                "count": len(issues),
                "max_results": max_results,
                "jql": jql,
                "issues": issues
            }

    except httpx.HTTPStatusError as e:
        log(f"ERROR: JIRA API error: {e.response.status_code}")
        log(f"ERROR: {e.response.text}")
        return {
            "error": f"JIRA API error: {e.response.status_code}",
            "detail": e.response.text,
            "issues": []
        }
    except Exception as e:
        log(f"ERROR: Failed to query JIRA: {e}")
        return {
            "error": f"Failed to query JIRA: {str(e)}",
            "issues": []
        }


def extract_text_from_adf(adf_doc: dict) -> str:
    """
    Extract plain text from Atlassian Document Format (ADF).

    ADF is a JSON structure used by modern JIRA for rich text fields.
    """
    if not isinstance(adf_doc, dict):
        return str(adf_doc)

    text_parts = []

    def extract_content(node):
        if isinstance(node, dict):
            # Text nodes have a "text" field
            if "text" in node:
                text_parts.append(node["text"])

            # Recursively process content array
            if "content" in node and isinstance(node["content"], list):
                for child in node["content"]:
                    extract_content(child)

    extract_content(adf_doc)
    return " ".join(text_parts)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Query JIRA for CVE-related security issues.",
        epilog="""
AUTHENTICATION:
  Requires JIRA credentials from environment variables:
    JIRA_HOST (default: redhat.atlassian.net)
    JIRA_EMAIL (required)
    JIRA_API_TOKEN (required)

  To create a JIRA API token:
    1. Go to https://id.atlassian.com/manage-profile/security/api-tokens
    2. Click "Create API token"
    3. Set as environment variable: export JIRA_API_TOKEN="your-token"

OUTPUT FORMAT:
  JSON object with "issues" array, each containing:
    - key: JIRA issue key (e.g., "DISCOVERY-1234")
    - summary: Issue title
    - description: Full issue description (plain text extracted from ADF)
    - status: Current issue status
    - labels: All issue labels
    - cve_ids: CVE IDs extracted from labels, summary, and description
    - package_name: Upstream package name parsed from summary (e.g., "Axios", "urllib3").
        Present in ~85% of issues. This is the upstream name, not the RPM name.
        Absent (null) in a minority of older issues that omit the "PackageName:" prefix.
    - vulnerable_package_nvrs: VULNERABLE package NVRs (NOT fixed versions).
        Only present in newer issues that include an AI_ONLY_REPORT block.
        Format: "package: <nvr>" e.g. "python-pip-26.0.1-2.1.hum1".
        Absent in older issues. Use Errata/Prograde data to find fixed NVRs.
    - upstream_fixed_versions: Upstream semver versions mentioned as fixed in description
        prose (e.g., "1.15.1", "11.1.0"). These are NOT RPM NVRs — they are the
        upstream project versions. Present in some but not all issues.
    - downstream_component: Value of the "Downstream Component Name" custom field
        (customfield_10669). Consistently populated across all issue generations.
        Covers both naming conventions: "discovery/discovery-server-rhel9" and
        "redhat-user-workloads/discovery-server". Null if not set.
    - created: ISO 8601 timestamp
    - updated: ISO 8601 timestamp
    - duedate: Due date (YYYY-MM-DD format, or null if not set)
    - assignee: Assignee display name (if assigned)
    - reporter: Reporter display name
    - linked_issues: Array of related JIRA issues (parent/child, blocks, etc.)
    - custom_fields: Dictionary of custom field values
    - url: Direct link to issue in JIRA

CVE EXTRACTION:
  CVE IDs are extracted from multiple sources:
    1. JIRA labels (e.g., "CVE-2026-1234")
    2. Issue summary text
    3. Issue description text

  This ensures all CVEs mentioned in the issue are captured, even if not
  properly tagged as labels.

RESULT ORDERING:
  Results are ordered by due date (ascending - oldest/most urgent first).
  This ensures that when limiting results with --max-results, you see the
  issues that are due soonest. Issues without a due date appear last.

DATE FILTERING:
  By default, only issues created in the last 90 days are returned. This
  prevents very old resolved issues from cluttering results. CVEs rarely
  remain unresolved for more than 2 months in practice.
    --since 2026-01-01     only issues created on or after Jan 1, 2026
    --since none           disable the filter entirely (may return very old issues)

TYPICAL USE CASES:
  1. Find all open CVE issues for your team
  2. Cross-reference JIRA CVEs with Prograde advisories
  3. Track CVE remediation status
  4. Link CVEs to affected components via custom fields

EXAMPLES:
  # Search for open CVE issues in DISCOVERY project
  %(prog)s --summary-contains "CVE"

  # Search with custom status filter
  %(prog)s --summary-contains "CVE" --status-in "To Do" "In Progress"

  # Search with label filter
  %(prog)s --label "Security" --status-in "Open"

  # Search in different project
  %(prog)s --project "PLATFORM" --summary-contains "CVE"

  # Get all CVE issues regardless of status
  %(prog)s --summary-contains "CVE" --no-status-filter

  # Extract only CVE IDs
  %(prog)s | jq -r '.issues[].cve_ids[]' | sort -u

  # Find issues with specific CVE
  %(prog)s | jq '.issues[] | select(.cve_ids[] | contains("CVE-2026"))'

  # Cross-reference with Prograde advisories
  query-jira-cves.py | jq -r '.issues[].cve_ids[]' | sort -u > jira-cves.txt
  parse-prograde-advisories.py emails.json | jq -r '... | .advisory_id' | while read id; do
    query-errata-advisory.py "$id" | jq -r '.cve_ids[]'
  done | sort -u > prograde-cves.txt
  comm -12 jira-cves.txt prograde-cves.txt  # CVEs in both JIRA and Prograde

NOTE:
  All logs and error messages go to stderr.
  Only JSON output goes to stdout.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        '--project',
        default=_JIRA_PROJECT,
        metavar='KEY',
        help='JIRA project key to search (default: $JIRA_PROJECT or "DISCOVERY")',
    )
    parser.add_argument(
        '--label',
        metavar='LABEL',
        help='Label to filter by (optional, no default)',
    )
    parser.add_argument(
        '--summary-contains',
        metavar='TEXT',
        help='Search for text in issue summary/title (e.g., "CVE" to find CVE-related issues)',
    )
    parser.add_argument(
        '--since',
        dest='created_since',
        metavar='YYYY-MM-DD',
        default='90daysago',
        help='Only return issues created on or after this date (default: 90 days ago). '
             'Use "none" to disable the filter and return all issues regardless of age.',
    )
    parser.add_argument(
        '--status-in',
        nargs='+',
        metavar='STATUS',
        help='Filter by status IN (e.g., "Open" "In Progress"). Mutually exclusive with --status-not-in.',
    )
    parser.add_argument(
        '--status-not-in',
        nargs='+',
        metavar='STATUS',
        help='Filter by status NOT IN (default: "Done" "Closed")',
    )
    parser.add_argument(
        '--no-status-filter',
        action='store_true',
        help='Do not filter by status (returns issues in any status)',
    )
    parser.add_argument(
        '--max-results',
        type=int,
        default=100,
        metavar='N',
        help='Maximum number of issues to return (default: 100)',
    )

    args = parser.parse_args()

    # Validate mutually exclusive args
    if args.status_in and args.status_not_in:
        log("ERROR: --status-in and --status-not-in are mutually exclusive")
        sys.exit(1)

    try:
        # Get credentials
        jira_host, jira_email, jira_api_token = get_jira_credentials()
        log(f"Connecting to JIRA: {jira_host}")

        # Determine status filter
        status_in = args.status_in
        status_not_in = args.status_not_in

        if args.no_status_filter:
            status_in = None
            status_not_in = None
        elif not status_in and not status_not_in:
            # Default: exclude Done and Closed
            status_not_in = ["Done", "Closed"]

        # Resolve the --since date filter
        created_since = None
        if args.created_since and args.created_since.lower() != "none":
            if args.created_since == "90daysago":
                from datetime import date, timedelta
                created_since = (date.today() - timedelta(days=90)).isoformat()
            else:
                created_since = args.created_since
            log(f"Filtering issues created since: {created_since}")

        # Search JIRA
        result = search_jira_issues(
            jira_host=jira_host,
            email=jira_email,
            api_token=jira_api_token,
            project=args.project if args.project else None,
            label=args.label if args.label else None,
            summary_contains=args.summary_contains if args.summary_contains else None,
            created_since=created_since,
            status_in=status_in,
            status_not_in=status_not_in,
            max_results=args.max_results,
        )

        # Output JSON to stdout (only this goes to stdout!)
        print(json.dumps(result, indent=2))

    except ValueError as e:
        log(f"CONFIGURATION ERROR: {e}")
        sys.exit(1)
    except Exception as e:
        log(f"FATAL ERROR: {e}")
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
