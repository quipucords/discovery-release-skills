#!/usr/bin/env python3
"""Verify the current working directory is this project's root.

Replaces the complex bash root-finding block in skill invocations.
Covered by the Bash(python3 .claude/skills/*) allowlist permission when
the user is already in the project root (the expected common case).

This script cannot cd the parent shell — it verifies location only.
If the user is not in the project root, it exits non-zero with
instructions. Skills must be invoked from the project root directory.

Also creates cve-data/ if it doesn't already exist.

All output goes to stderr. Exits 0 on success, 1 on failure.
"""
import os
import sys

MARKER = os.path.join(".claude", "skills")


def find_root(start: str) -> str | None:
    d = start
    while True:
        if os.path.isdir(os.path.join(d, ".claude", "skills")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


cwd = os.getcwd()

if os.path.isdir(os.path.join(cwd, ".claude", "skills")):
    os.makedirs("cve-data", exist_ok=True)
    print(f"Working directory: {cwd}", file=sys.stderr)
    sys.exit(0)

root = find_root(cwd)
if root:
    print(f"Error: not in the project root.", file=sys.stderr)
    print(f"  Project root found at: {root}", file=sys.stderr)
    print(f"  Run this first: cd {root}", file=sys.stderr)
else:
    print(f"Error: cannot find project root (.claude/skills/ not found).", file=sys.stderr)
    print(f"  Navigate to the discovery-cve-skills directory and try again.", file=sys.stderr)

sys.exit(1)
