#!/usr/bin/env python3
"""Validate all prerequisites for the query-all-cves pipeline.

Checks all requirements up front so the user knows everything that needs
fixing before any long-running data collection begins.

Checks:
  - Kerberos ticket valid (required for query-errata-advisory)
  - JIRA_EMAIL set (required for query-jira-cves)
  - JIRA_API_TOKEN set (required for query-jira-cves)
"""
import os
import subprocess
import sys

errors = []

result = subprocess.run(["klist", "-s"], capture_output=True)
if result.returncode != 0:
    errors.append(
        "No valid Kerberos ticket.\n"
        "  Fix: kinit --keychain -V <username>@YOUR_KERBEROS_REALM"
    )

if not os.environ.get("JIRA_EMAIL"):
    errors.append(
        "JIRA_EMAIL is not set.\n"
        "  Fix: add it to the env block in ~/.claude/settings.json (see project README)"
    )

if not os.environ.get("JIRA_API_TOKEN"):
    errors.append(
        "JIRA_API_TOKEN is not set.\n"
        "  Fix: add it to the env block in ~/.claude/settings.json (see project README)"
    )

if errors:
    print("Prerequisite checks failed:\n", file=sys.stderr)
    for i, err in enumerate(errors, 1):
        print(f"  {i}. {err}", file=sys.stderr)
    sys.exit(1)

print("All prerequisites OK.")
