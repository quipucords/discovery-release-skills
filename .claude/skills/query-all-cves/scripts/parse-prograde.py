#!/usr/bin/env python3
"""Parse prograde-emails.json → prograde-advisories.json.

Wraps parse-prograde-advisories in a script so the stdout redirect is handled
here — eliminating any risk of Claude adding 2>&1 to the invocation, which
would corrupt the JSON output with progress log lines.
"""
import json
import subprocess
import sys

with open("cve-data/prograde-advisories.json", "w") as out:
    result = subprocess.run(
        ["uv", "run",
         ".claude/skills/parse-prograde-advisories/scripts/parse-prograde-advisories.py",
         "cve-data/prograde-emails.json"],
        stdout=out,
    )

if result.returncode != 0:
    print("Error: parse-prograde-advisories failed.", file=sys.stderr)
    sys.exit(1)

with open("cve-data/prograde-advisories.json") as f:
    count = len(json.load(f).get("advisories", []))
print(f"Parsed prograde emails: {count} advisories → cve-data/prograde-advisories.json",
      file=sys.stderr)
