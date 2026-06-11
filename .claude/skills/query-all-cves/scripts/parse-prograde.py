#!/usr/bin/env python3
"""Parse prograde-emails.json → prograde-advisories.json.

Wraps parse-prograde-advisories in a script so the stdout redirect is handled
here — eliminating any risk of Claude adding 2>&1 to the invocation, which
would corrupt the JSON output with progress log lines.
"""
import subprocess
import sys

result = subprocess.run(
    ["uv", "run",
     ".claude/skills/parse-prograde-advisories/scripts/parse-prograde-advisories.py",
     "cve-data/prograde-emails.json"],
    stdout=open("cve-data/prograde-advisories.json", "w"),
)

if result.returncode != 0:
    print("Error: parse-prograde-advisories failed.", file=sys.stderr)
    sys.exit(1)

import json
count = len(json.load(open("cve-data/prograde-advisories.json")).get("advisories", []))
print(f"Parsed prograde emails: {count} advisories → cve-data/prograde-advisories.json")
