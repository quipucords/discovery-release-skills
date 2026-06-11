#!/usr/bin/env python3
"""Validate that each given file exists and contains valid JSON.

Usage: python3 validate-json-files.py file1.json file2.json ...
Exits non-zero if any file is missing or contains invalid JSON.
"""
import json
import sys

files = sys.argv[1:]
if not files:
    print("Usage: validate-json-files.py file1.json [file2.json ...]")
    sys.exit(1)

failed = []
for f in files:
    try:
        json.load(open(f))
        print(f"  OK:   {f}")
    except FileNotFoundError:
        print(f"  FAIL: {f}: file not found", file=sys.stderr)
        failed.append(f)
    except json.JSONDecodeError as e:
        print(f"  FAIL: {f}: invalid JSON — {e}", file=sys.stderr)
        print(f"        (if the file contains log lines, 2>&1 was used — never mix stderr into data files)",
              file=sys.stderr)
        failed.append(f)

if failed:
    print(f"\nError: {len(failed)} file(s) failed validation.", file=sys.stderr)
    sys.exit(1)
