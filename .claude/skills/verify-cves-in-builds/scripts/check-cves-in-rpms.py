#!/usr/bin/env python3
"""Compare CVE fix data against installed RPMs in pulled container images.

Reads:
  cve-data/unified-cves.json   — CVE records with vulnerable_packages + fixed_packages
  cve-data/rpms-server.txt     — rpm -qa output from discovery-server image
  cve-data/rpms-ui.txt         — rpm -qa output from discovery-ui image
  cve-data/checked-images.json — mapping of container name → image URL checked

Writes:
  cve-data/verified-cves.json  — unified-cves.json enriched with checked_containers
                                  per CVE, showing what was found and whether it's fixed

All progress messages go to stderr. This script produces no stdout output
(results are written to cve-data/verified-cves.json). Exits non-zero on failure.
"""
import json
import re
import sys
from datetime import datetime, timezone

SERVER_CONTAINER = "discovery/discovery-server-rhel9"
UI_CONTAINER     = "discovery/discovery-ui-rhel9"

RPM_FILES = {
    SERVER_CONTAINER: "cve-data/rpms-server.txt",
    UI_CONTAINER:     "cve-data/rpms-ui.txt",
}

SEVERITY_ORDER = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1, "Unknown": 0}


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ── RPM parsing and version comparison ───────────────────────────────────────

NVRA_RE = re.compile(r'^(.+?)-([^-]+)-([^-]+)\.([^.]+)$')
EPOCH_RE = re.compile(r'^(\d+):(.+)$')
NAME_VERSION_START_RE = re.compile(r'-(\d)')


def parse_nvra(nvra: str) -> dict | None:
    """Parse 'name-version-release.arch' into components. Returns None if unparseable."""
    m = NVRA_RE.match(nvra.strip())
    if not m:
        return None
    return {"name": m.group(1), "version": m.group(2), "release": m.group(3), "arch": m.group(4)}


def parse_evr(s: str) -> tuple[str, str, str]:
    """Parse a version string into (epoch, version, release) for comparison."""
    # Strip leading package name if present (e.g. "nginx-1.24.0-6.el9" → "1.24.0-6.el9")
    if s and not s[0].isdigit() and ":" not in s[:3]:
        m = NAME_VERSION_START_RE.search(s)
        if m:
            s = s[m.start() + 1:]

    epoch = "0"
    m = EPOCH_RE.match(s)
    if m:
        epoch, s = m.group(1), m.group(2)

    parts = s.rsplit("-", 1)
    if len(parts) == 2:
        return (epoch, parts[0], parts[1])
    return (epoch, s, "0")


def evr_gte(installed_vr: str, fixed_nvr: str) -> bool:
    """Return True if installed version-release >= fixed NVR (package name stripped)."""
    installed_evr = parse_evr(installed_vr)
    fixed_evr = parse_evr(fixed_nvr)
    return installed_evr >= fixed_evr


def package_name_from_entry(entry: dict) -> str | None:
    """Extract the base RPM package name from a vulnerable_packages or fixed_packages entry."""
    if entry.get("name"):
        return entry["name"]
    # Fall back to parsing from nvr or rpm_nvras
    nvr = entry.get("nvr") or next(iter(entry.get("rpm_nvras", [])), None)
    if nvr:
        m = NAME_VERSION_START_RE.search(nvr)
        if m:
            return nvr[:m.start()]
    return None


# ── Load input files ──────────────────────────────────────────────────────────

def load_json(path: str, label: str) -> dict | None:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        log(f"Error: {label} not found: {path}")
        return None
    except json.JSONDecodeError as e:
        log(f"Error: {label} is not valid JSON ({path}): {e}")
        return None


def load_rpm_list(path: str) -> tuple[dict[str, list[dict]], list[str]]:
    """
    Load an rpm -qa output file and index packages by name.
    Returns (index, skipped) where index maps package name → list of parsed
    NVRA dicts, and skipped is a list of lines that could not be parsed.
    """
    index: dict[str, list[dict]] = {}
    skipped: list[str] = []
    try:
        with open(path) as f:
            for line in f:
                nvra = line.strip()
                if not nvra:
                    continue
                parsed = parse_nvra(nvra)
                if parsed:
                    name = parsed["name"]
                    index.setdefault(name, []).append({**parsed, "nvra": nvra})
                else:
                    skipped.append(nvra)
    except FileNotFoundError:
        log(f"Error: RPM list not found: {path}")
        return index, skipped
    if skipped:
        log(f"  Skipped {len(skipped)} unparseable line(s) in {path} "
            f"(e.g. gpg-pubkey entries with no arch suffix): {', '.join(skipped[:3])}")
    return index, skipped


log("Loading input files...")

unified = load_json("cve-data/unified-cves.json", "unified-cves.json")
checked_images = load_json("cve-data/checked-images.json", "checked-images.json")

if not unified or not checked_images:
    sys.exit(1)

rpm_index: dict[str, dict[str, list[dict]]] = {}
skipped_nvras: dict[str, list[str]] = {}
for container, path in RPM_FILES.items():
    if container in checked_images:
        rpm_index[container], skipped_nvras[container] = load_rpm_list(path)
        log(f"  Loaded {sum(len(v) for v in rpm_index[container].values())} packages "
            f"from {path}")
    else:
        log(f"  Skipping {container}: not in checked-images.json (was not pulled)")


# ── Check each CVE against container RPM lists ───────────────────────────────

def check_cve_in_container(cve: dict, container: str) -> dict:
    """
    Return a checked_containers entry for one CVE + container combination.
    """
    result = {
        "checked_image": checked_images.get(container),
        "package_found": False,
        "searched_names": [],
        "installed_nvras": [],
        "minimum_fixed_nvr": None,
        "is_fixed": None,
    }

    # Build a map of package name → minimum fixed NVR from fixed_packages.
    # fixed_packages may list multiple NVRs for the same package across different
    # RHEL releases; we keep the earliest (minimum) to avoid false "fixed" verdicts.
    fixed_by_name: dict[str, str] = {}
    for fp in cve.get("fixed_packages", []):
        name = package_name_from_entry(fp)
        nvr  = fp.get("nvr")
        if name and nvr:
            if name not in fixed_by_name or parse_evr(nvr) < parse_evr(fixed_by_name[name]):
                fixed_by_name[name] = nvr

    # Collect candidate package names from both vulnerable_packages and fixed_packages.
    # We search both because:
    #   - vulnerable_packages (from catalog) has the richest name data
    #   - fixed_packages (from errata) catches CVEs where catalog data is sparse
    #     (e.g. JIRA-only CVEs that have no catalog vulnerable_packages entry)
    search_names: set[str] = set()
    for vp in cve.get("vulnerable_packages", []):
        name = package_name_from_entry(vp)
        if name:
            search_names.add(name)
    search_names.update(fixed_by_name.keys())

    result["searched_names"] = sorted(search_names)

    if not search_names:
        return result

    container_index = rpm_index.get(container, {})

    found_nvras: list[str] = []
    relevant_fixed_nvr: str | None = None

    for name in search_names:
        matches = container_index.get(name, [])
        for m in matches:
            found_nvras.append(m["nvra"])
        if name in fixed_by_name and (relevant_fixed_nvr is None or
                parse_evr(fixed_by_name[name]) < parse_evr(relevant_fixed_nvr)):
            relevant_fixed_nvr = fixed_by_name[name]

    result["installed_nvras"] = sorted(found_nvras)
    result["minimum_fixed_nvr"] = relevant_fixed_nvr

    if not found_nvras:
        return result  # package_found stays False, is_fixed stays None

    result["package_found"] = True

    if relevant_fixed_nvr is None:
        return result  # is_fixed stays None — fix version unknown

    # is_fixed = True only if ALL matching packages are at or above the fixed version
    all_fixed = all(
        evr_gte(f"{m['version']}-{m['release']}", relevant_fixed_nvr)
        for name in search_names
        for m in container_index.get(name, [])
    )
    result["is_fixed"] = all_fixed
    return result


log(f"\nChecking {len(unified['cves'])} CVEs against container RPM lists...")
import time
t0 = time.time()

enriched_cves = []
stats = {c: {"found": 0, "fixed": 0, "not_fixed": 0, "unknown": 0, "not_found": 0}
         for c in checked_images}

for cve in unified["cves"]:
    cve_out = dict(cve)
    checked_containers: dict[str, dict] = {}

    for container in cve.get("affected_containers", []):
        if container not in rpm_index:
            log(f"  Warning: {cve['cve_id']} affects {container} but no RPM list was loaded "
                f"for it — skipping this container")
            continue
        entry = check_cve_in_container(cve, container)
        checked_containers[container] = entry

        s = stats[container]
        if entry["package_found"]:
            s["found"] += 1
            if entry["is_fixed"] is True:
                s["fixed"] += 1
            elif entry["is_fixed"] is False:
                s["not_fixed"] += 1
            else:
                s["unknown"] += 1
        elif entry["searched_names"]:
            # We knew what to look for but didn't find it
            s["not_found"] += 1

    cve_out["checked_containers"] = checked_containers
    enriched_cves.append(cve_out)

log(f"Checked {len(enriched_cves)} CVEs in {time.time() - t0:.1f}s.")


# ── Build output ──────────────────────────────────────────────────────────────

output = {
    "generated_at": unified.get("generated_at"),
    "verified_at": datetime.now(timezone.utc).isoformat(),
    "verification": {
        "images": dict(checked_images),
        "skipped_nvras": skipped_nvras,
    },
    "summary": unified.get("summary", {}),
    "verification_summary": {
        container: {
            "checked_image": checked_images.get(container),
            **s,
        }
        for container, s in stats.items()
    },
    "cves": enriched_cves,
}

with open("cve-data/verified-cves.json", "w") as f:
    json.dump(output, f, indent=2)

log(f"\nWrote cve-data/verified-cves.json ({len(enriched_cves)} CVEs)")
