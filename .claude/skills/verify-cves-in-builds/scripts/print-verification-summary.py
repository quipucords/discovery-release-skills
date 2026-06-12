#!/usr/bin/env python3
"""Print a human-readable summary of CVE verification results.

Single-set mode (default):
  Reads cve-data/verified-cves-downstream.json. Output is identical to the
  previous single-image report.

Comparison mode (--comparison):
  Reads cve-data/comparison.json. Shows a delta summary followed by per-set
  detail sections.

All output goes to stdout. Errors go to stderr.
Exits non-zero if the input file is missing or unreadable.
"""
import argparse
import json
import sys

SEVERITY_ORDER = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1, "Unknown": 0}

sev_key = lambda c: -SEVERITY_ORDER.get(c.get("severity") or "Unknown", 0)

parser = argparse.ArgumentParser()
parser.add_argument("--comparison", action="store_true",
                    help="Read comparison.json and show upstream vs. downstream delta report")
args = parser.parse_args()


def load_json(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: {path} not found.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: {path} is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)


# ── Comparison mode ───────────────────────────────────────────────────────────

def print_comparison_report(data: dict) -> None:
    cves = data.get("cves", [])

    print("CVE Comparison Report")
    print(f"  Generated at: {data.get('generated_at', 'unknown')}")
    print()

    by_delta: dict[str, list] = {}
    for cve in cves:
        by_delta.setdefault(cve.get("delta", "unknown"), []).append(cve)

    action_deltas = [
        "fixed_upstream_not_downstream",
        "not_fixed_in_either",
        "fixed_downstream_not_upstream",
        "unknown",
    ]
    has_action = any(by_delta.get(d) for d in action_deltas)

    if has_action:
        print("  *** ACTION REQUIRED ***")
        print()

        group = by_delta.get("fixed_upstream_not_downstream", [])
        if group:
            group.sort(key=sev_key)
            print(f"  Backport candidates — fixed upstream, NOT fixed downstream ({len(group)} CVE(s)):")
            print("  (These fixes exist in the upstream quay.io images but have not yet been")
            print("   shipped in the downstream registry.redhat.io images.)")
            print()
            for cve in group:
                print(f"    [{(cve.get('severity') or '?'):9s}] {cve['cve_id']}")
                print(f"               {cve.get('cve_link', '')}")
            print()

        group = by_delta.get("not_fixed_in_either", [])
        if group:
            group.sort(key=sev_key)
            print(f"  Not fixed in either downstream or upstream ({len(group)} CVE(s)):")
            print()
            for cve in group:
                print(f"    [{(cve.get('severity') or '?'):9s}] {cve['cve_id']}")
            print()

        group = by_delta.get("fixed_downstream_not_upstream", [])
        if group:
            group.sort(key=sev_key)
            print(f"  Regression — fixed downstream but NOT in upstream ({len(group)} CVE(s)):")
            print("  (These fixes are present in the downstream release but have been lost in upstream.)")
            print()
            for cve in group:
                print(f"    [{(cve.get('severity') or '?'):9s}] {cve['cve_id']}")
            print()

        group = by_delta.get("unknown", [])
        if group:
            group.sort(key=sev_key)
            print(f"  UNKNOWN — manual verification needed ({len(group)} CVE(s)):")
            print("  (No RPM package data available; may be non-RPM dependencies.)")
            print()
            for cve in group:
                print(f"    [{(cve.get('severity') or '?'):9s}] {cve['cve_id']}")
            print()

        print("  *** END ACTION REQUIRED ***")
        print()

    fixed_both = len(by_delta.get("fixed_in_both", []))
    print(f"  No action needed (fixed in both): {fixed_both} CVE(s)")
    print()


# ── Single-set mode (unchanged logic, new filename) ───────────────────────────

def print_single_set_report(data: dict) -> None:
    verification = data.get("verification", {})
    images       = verification.get("images", {})
    skipped_nvras = verification.get("skipped_nvras", {})
    vsummary     = data.get("verification_summary", {})
    cves         = data.get("cves", [])

    any_skipped = {c: lines for c, lines in skipped_nvras.items() if lines}

    all_no_pkg_data = []
    for container in images:
        for cve in cves:
            entry = cve.get("checked_containers", {}).get(container, {})
            if (entry.get("package_found") is False
                    and not entry.get("searched_names")
                    and container in cve.get("affected_containers", [])):
                all_no_pkg_data.append((cve, container))

    print("CVE Build Verification Report")
    print(f"  Verified at: {data.get('verified_at', 'unknown')}")
    print()

    if any_skipped or all_no_pkg_data:
        print("  *** ACTION REQUIRED — Manual verification needed for the following ***")
        print()

        if any_skipped:
            print("  RPM entries that could not be parsed and were excluded from verification:")
            print("  (Check whether any are relevant to the CVEs in this report.)")
            print()
            for container, lines in any_skipped.items():
                print(f"    {container.split('/')[-1]}:")
                for line in lines:
                    print(f"      {line}")
            print()

        if all_no_pkg_data:
            print("  CVEs marked UNKNOWN — affect the container but have no RPM package data:")
            print("  (May be non-RPM dependencies such as npm or Python packages.")
            print("   Cannot be verified automatically. Investigate each one manually.)")
            print()
            for cve, container in sorted(all_no_pkg_data,
                                         key=lambda x: -SEVERITY_ORDER.get(
                                             x[0].get("severity") or "Unknown", 0)):
                sev = cve.get("severity") or "?"
                print(f"    [{sev:9s}] {cve['cve_id']}  ({container.split('/')[-1]})")
                print(f"               {cve.get('cve_link', '')}")
            print()

        print("  *** END ACTION REQUIRED ***")
        print()

    for container, image in images.items():
        s = vsummary.get(container, {})
        print(f"  {container}")
        print(f"    Checked image:          {image}")
        print(f"    Fixed in build:         {s.get('fixed', 0)}")
        print(f"    NOT fixed in build:     {s.get('not_fixed', 0)}")
        print(f"    Could not verify:       {s.get('not_found', 0)}  ← package not found in container")
        print(f"    UNKNOWN (no RPM data):  {s.get('no_package_data', 0)}  ← see ACTION REQUIRED above")
        print(f"    Fix status unknown:     {s.get('unknown', 0)}  ← found but no fix NVR available")
        print()

    for container in images:
        unfixed        = []
        not_found      = []
        no_pkg_data    = []
        status_unknown = []

        for cve in cves:
            entry    = cve.get("checked_containers", {}).get(container, {})
            is_fixed = entry.get("is_fixed")
            if is_fixed is False:
                unfixed.append(cve)
            elif entry.get("package_found") is False and entry.get("searched_names"):
                not_found.append(cve)
            elif (entry.get("package_found") is False and not entry.get("searched_names")
                    and container in cve.get("affected_containers", [])):
                no_pkg_data.append(cve)
            elif is_fixed is None and entry.get("package_found") is True:
                status_unknown.append(cve)

        if not unfixed and not not_found and not no_pkg_data and not status_unknown:
            print(f"  {container}: all checked CVEs are fixed. ✓")
            print()
            continue

        if unfixed:
            unfixed.sort(key=sev_key)
            print(f"  {container}: {len(unfixed)} unfixed CVE(s):")
            for cve in unfixed:
                entry     = cve["checked_containers"][container]
                installed = ", ".join(entry.get("installed_nvras") or ["?"])
                fixed_nvr = entry.get("minimum_fixed_nvr") or "?"
                print(f"    [{(cve.get('severity') or '?'):9s}] {cve['cve_id']}")
                print(f"               installed: {installed}")
                print(f"               needs:     {fixed_nvr}")
            print()

        if not_found:
            not_found.sort(key=sev_key)
            print(f"  {container}: {len(not_found)} CVE(s) could not be verified —"
                  f" package not found in container, check manually:")
            for cve in not_found:
                entry = cve["checked_containers"][container]
                names = ", ".join(entry.get("searched_names") or ["?"])
                print(f"    [{(cve.get('severity') or '?'):9s}] {cve['cve_id']}")
                print(f"               searched for: {names}")
            print()

        if no_pkg_data:
            no_pkg_data.sort(key=sev_key)
            print(f"  {container}: {len(no_pkg_data)} CVE(s) marked UNKNOWN (see ACTION REQUIRED above):")
            for cve in no_pkg_data:
                print(f"    [{(cve.get('severity') or '?'):9s}] {cve['cve_id']}")
            print()

        if status_unknown:
            status_unknown.sort(key=sev_key)
            print(f"  {container}: {len(status_unknown)} CVE(s) found in container"
                  f" but fix version unknown:")
            for cve in status_unknown:
                entry     = cve["checked_containers"][container]
                installed = ", ".join(entry.get("installed_nvras") or ["?"])
                print(f"    [{(cve.get('severity') or '?'):9s}] {cve['cve_id']}")
                print(f"               installed: {installed}")
                print(f"               fixed NVR: unknown")
            print()

    print(f"Full report: cve-data/verified-cves-downstream.json")


# ── Dispatch ──────────────────────────────────────────────────────────────────

if args.comparison:
    data = load_json("cve-data/comparison.json")
    print_comparison_report(data)
else:
    data = load_json("cve-data/verified-cves-downstream.json")
    print_single_set_report(data)
