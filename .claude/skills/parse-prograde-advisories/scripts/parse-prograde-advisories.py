#!/usr/bin/env python3
# /// script
# dependencies = [
#     "beautifulsoup4>=4.12.0",
# ]
# ///
"""
Parse Prograde email JSON to extract CVE advisory details.

Reads JSON output from query-gmail.py and extracts advisory information from HTML email bodies.
All logs and errors go to stderr; only JSON results go to stdout.
"""

import argparse
import json
import re
import sys
from typing import Any

from bs4 import BeautifulSoup


def log(message: str) -> None:
    """Log to stderr."""
    print(message, file=sys.stderr)


def extract_advisory_details(email: dict[str, Any]) -> dict[str, Any] | None:
    """
    Extract advisory details from Prograde email body.

    Returns dict with extracted fields or None if not a valid Prograde email.
    """
    message_id = email.get("message_id", "")
    subject = email.get("subject", "")
    date = email.get("date", "")
    body = email.get("body", "")

    # Check if this is a Prograde email
    if "[Prograde]" not in subject:
        log(f"Skipping non-Prograde email: {subject}")
        return None

    # Parse HTML body
    soup = BeautifulSoup(body, 'html.parser')

    # Extract text content for regex matching
    # BeautifulSoup will help us handle HTML entities and structure
    body_text = str(soup)

    # Extract advisory link
    advisory_link = None
    advisory_id = None
    link_match = re.search(r'https://errata\.engineering\.redhat\.com/advisory/(\d+)', body_text)
    if link_match:
        advisory_link = link_match.group(0)
        advisory_id = link_match.group(1)

    # Extract advisory synopsis
    # Pattern: <b>Advisory synopsis:</b> {text}<br or newline or <
    advisory_synopsis = None
    synopsis_match = re.search(r'Advisory synopsis:(?:</b>)?\s*([^\n<]+)', body_text, re.IGNORECASE)
    if synopsis_match:
        advisory_synopsis = synopsis_match.group(1).strip()

    # Extract advisory security impact
    # Pattern: <b>Advisory security impact:</b> {severity}<br
    advisory_security_impact = None
    impact_match = re.search(r'Advisory security impact:(?:</b>)?\s*(\w+)', body_text, re.IGNORECASE)
    if impact_match:
        advisory_security_impact = impact_match.group(1).strip()

    # Extract affected container repositories from HTML table
    # The table has headers: Repository, Build, Tags, Image Owners, Program Managers
    # We want to extract all repository names (e.g., "discovery/discovery-server-rhel9")
    container_repositories = []

    # Find all table rows
    for row in soup.find_all('tr'):
        cells = row.find_all('td')
        if cells:
            # First cell contains the repository
            first_cell = cells[0]
            # Repository is wrapped in <ul> tags
            ul_tags = first_cell.find_all('ul')
            for ul in ul_tags:
                repo_text = ul.get_text(strip=True)
                if repo_text and repo_text != "none":
                    container_repositories.append(repo_text)

    # Deduplicate while preserving order
    seen = set()
    unique_repos = []
    for repo in container_repositories:
        if repo not in seen:
            seen.add(repo)
            unique_repos.append(repo)

    # Only return if we found at least the advisory link
    if not advisory_link:
        log(f"WARNING: Could not extract advisory link from Prograde email: {subject}")
        return None

    return {
        "message_id": message_id,
        "subject": subject,
        "date": date,
        "advisory_link": advisory_link,
        "advisory_id": advisory_id,
        "advisory_synopsis": advisory_synopsis,
        "advisory_security_impact": advisory_security_impact,
        "affected_containers": unique_repos,
    }


def parse_prograde_emails(input_data: dict[str, Any]) -> dict[str, Any]:
    """
    Parse Prograde emails and extract advisory details.

    Args:
        input_data: JSON dict with "messages" list from query-gmail.py

    Returns:
        Dict with "advisories" list containing extracted details
    """
    messages = input_data.get("messages", [])
    log(f"Processing {len(messages)} messages")

    advisories = []
    for email in messages:
        advisory = extract_advisory_details(email)
        if advisory:
            advisories.append(advisory)

    log(f"Extracted {len(advisories)} advisory details")

    return {"advisories": advisories}


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Extract CVE advisory details from Prograde email JSON.",
        epilog="""
INPUT FORMAT:
  Expects JSON from query-gmail.py with structure:
    {"messages": [{"message_id": "...", "subject": "...", "body": "...", ...}]}

OUTPUT FORMAT:
  JSON object with "advisories" array, each containing:
    - message_id: Original Gmail message ID
    - subject: Original email subject
    - date: Email date (YYYY-MM-DD HH:MM:SS)
    - advisory_link: Full URL to errata advisory
    - advisory_id: Numeric advisory ID (e.g., "165721")
    - advisory_synopsis: Synopsis text (e.g., "Important: openssh security update")
    - advisory_security_impact: Severity (e.g., "Important", "Moderate")
    - affected_containers: List of container repository names (e.g., ["discovery/discovery-server-rhel9"])

  Example output:
    {
      "advisories": [
        {
          "message_id": "19e41d6f4e0d82bd",
          "subject": "[Prograde] Important: openssh security update RHSA 165721...",
          "date": "2026-05-19 13:04:26",
          "advisory_link": "https://[internal-errata-host]/advisory/165721",
          "advisory_id": "165721",
          "advisory_synopsis": "Important: openssh security update",
          "advisory_security_impact": "Important",
          "affected_containers": ["discovery/discovery-server-rhel9", "discovery/discovery-ui-rhel9"]
        }
      ]
    }

EXAMPLES:
  # From stdin (piped from query-gmail.py)
  query-gmail.py --label "alerts/prograde" --since "2026-05-01" | %(prog)s

  # From file
  %(prog)s prograde-emails.json

  # Explicitly from stdin
  cat prograde-emails.json | %(prog)s -

  # Extract only Important advisories using jq
  %(prog)s prograde-emails.json | jq '.advisories[] | select(.advisory_security_impact == "Important")'

  # Get unique advisory IDs
  %(prog)s prograde-emails.json | jq -r '.advisories[].advisory_id' | sort -u

  # Filter advisories affecting specific containers
  %(prog)s prograde-emails.json | jq '.advisories[] | select(.affected_containers[] | contains("discovery/discovery-server"))'

  # Get advisory IDs for Discovery containers only
  %(prog)s prograde-emails.json | jq -r '.advisories[] | select(.affected_containers[] | test("discovery/discovery-(server|ui)")) | .advisory_id'

USAGE WITH ERRATA ADVISORY API:
  The advisory_id field can be passed to errata-advisory-mcp tools:
    - get_advisory (get CVE IDs and metadata)
    - get_advisory_builds (get fixed package versions)
    - verify_prograde_advisory (complete CVE verification)

NOTE:
  All logs and error messages go to stderr.
  Only JSON output goes to stdout.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        'input_file',
        nargs='?',
        default='-',
        metavar='FILE',
        help='Path to JSON file from query-gmail.py, or "-" to read from stdin (default: -)',
    )

    args = parser.parse_args()

    try:
        # Read input JSON
        if args.input_file == '-':
            log("Reading JSON from stdin...")
            input_text = sys.stdin.read()
        else:
            log(f"Reading JSON from {args.input_file}")
            with open(args.input_file, 'r') as f:
                input_text = f.read()

        # Parse JSON
        try:
            input_data = json.loads(input_text)
        except json.JSONDecodeError as e:
            log(f"ERROR: Invalid JSON input: {e}")
            sys.exit(1)

        # Process emails
        result = parse_prograde_emails(input_data)

        # Output JSON to stdout (only this goes to stdout!)
        print(json.dumps(result, indent=2))

    except FileNotFoundError:
        log(f"ERROR: File not found: {args.input_file}")
        sys.exit(1)
    except Exception as e:
        log(f"FATAL ERROR: {e}")
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
