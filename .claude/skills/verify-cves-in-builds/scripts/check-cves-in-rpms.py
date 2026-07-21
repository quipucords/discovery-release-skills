#!/usr/bin/env python3
"""Compare CVE fix data against installed RPMs in pulled container images.

Reads:
  cve-data/unified-cves.json              — CVE records with vulnerable_packages + fixed_packages
  cve-data/rpms-server-{set}.txt          — rpm -qa output from discovery-server image
  cve-data/rpms-ui-{set}.txt              — rpm -qa output from discovery-ui image
  cve-data/checked-images-{set}.json      — mapping of container name → image URL checked
  (where {set} is "downstream" or "upstream", from the --set argument)

Writes:
  cve-data/verified-cves-{set}.json       — unified-cves.json enriched with checked_containers
                                             per CVE, showing what was found and whether it's fixed

All progress messages go to stderr. This script produces no stdout output
(results are written to cve-data/verified-cves-{set}.json). Exits non-zero on failure.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

_parser = argparse.ArgumentParser(
    description="Check CVEs against installed RPMs for one image set.")
_parser.add_argument("--set", required=True, choices=["downstream", "upstream"],
                     dest="set_name",
                     help="Image set to check: 'downstream' or 'upstream'")
_args = _parser.parse_args()
set_name = _args.set_name

# These constants must match the values in pull-and-query-rpms.py.
SERVER_CONTAINER = os.environ.get("DOWNSTREAM_SERVER_IMAGE", "registry.redhat.io/discovery/discovery-server-rhel9").split("/", 1)[1]
UI_CONTAINER     = os.environ.get("DOWNSTREAM_UI_IMAGE",     "registry.redhat.io/discovery/discovery-ui-rhel9").split("/", 1)[1]

RPM_FILES = {
    SERVER_CONTAINER: f"cve-data/rpms-server-{set_name}.txt",
    UI_CONTAINER:     f"cve-data/rpms-ui-{set_name}.txt",
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


def rpmvercmp(a: str, b: str) -> int:
    """Compare two RPM version or release strings using rpmvercmp algorithm.

    Returns -1, 0, or 1. Handles mixed numeric/alpha segments correctly:
    numeric segments are compared as integers (so "10" > "9"), alpha segments
    are compared lexicographically, and numeric always beats alpha.
    """
    if a == b:
        return 0

    i, j = 0, 0
    while True:
        # Skip non-alphanumeric, non-tilde characters
        while i < len(a) and not a[i].isalnum() and a[i] != "~":
            i += 1
        while j < len(b) and not b[j].isalnum() and b[j] != "~":
            j += 1

        # Tilde sorts before everything (pre-release marker)
        a_tilde = i < len(a) and a[i] == "~"
        b_tilde = j < len(b) and b[j] == "~"
        if a_tilde or b_tilde:
            if not a_tilde:
                return 1
            if not b_tilde:
                return -1
            i += 1
            j += 1
            continue

        if i >= len(a) and j >= len(b):
            return 0
        if i >= len(a):
            return -1
        if j >= len(b):
            return 1

        if a[i].isdigit():
            # Numeric segment — numeric always beats alpha
            i0, j0 = i, j
            while i < len(a) and a[i].isdigit():
                i += 1
            while j < len(b) and b[j].isdigit():
                j += 1
            if j0 < len(b) and not b[j0].isdigit():
                return 1  # numeric > alpha
            na, nb = int(a[i0:i]), int(b[j0:j])
            if na != nb:
                return -1 if na < nb else 1
        else:
            # Alpha segment
            i0, j0 = i, j
            while i < len(a) and a[i].isalpha():
                i += 1
            while j < len(b) and b[j].isalpha():
                j += 1
            if j0 < len(b) and b[j0].isdigit():
                return -1  # alpha < numeric
            sa, sb = a[i0:i], b[j0:j]
            if sa != sb:
                return -1 if sa < sb else 1


def evr_gte(installed_vr: str, fixed_nvr: str) -> bool:
    """Return True if installed version-release >= fixed NVR using rpmvercmp semantics."""
    installed_evr = parse_evr(installed_vr)
    fixed_evr = parse_evr(fixed_nvr)

    # Compare epoch as integers
    ei, ef = int(installed_evr[0]), int(fixed_evr[0])
    if ei != ef:
        return ei >= ef

    # Compare version, then release using rpmvercmp
    cmp = rpmvercmp(installed_evr[1], fixed_evr[1])
    if cmp != 0:
        return cmp > 0
    return rpmvercmp(installed_evr[2], fixed_evr[2]) >= 0


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


# Matches 'python-X' source package names (SRPM convention in RHEL).
_PYTHON_SRPM_RE = re.compile(r'^python-(.+)$')


def _expand_python_names(name: str, container_index: dict[str, list]) -> set[str]:
    """Expand a 'python-X' source package name to include binary RPM variants.

    RHEL publishes Python libraries under source package name 'python-X' but
    the installed binary packages are named 'python3-X', 'python3.12-X',
    'python3-X-wheel', 'python3.12-X-wheel', etc. The exact minor version
    depends on the RHEL version and may vary across releases.

    Scans the actual container RPM index to find all matching variants so we
    don't need a static lookup table. The version comparison in evr_gte()
    already strips the package name prefix, so binary and source NVRs compare
    correctly as long as they share the same upstream version number.
    """
    m = _PYTHON_SRPM_RE.match(name)
    if not m:
        return {name}
    suffix = re.escape(m.group(1))
    # Anchored at $ so 'python-pip' matches 'python3.12-pip' but NOT
    # 'python3.12-pip-wheel': wheel packages are a separate RPM and are only
    # relevant when the CVE itself targets 'python-pip-wheel' specifically.
    pattern = re.compile(rf'^python\d+(?:\.\d+)?-{suffix}$')
    expanded = {name}
    for key in container_index:
        if pattern.match(key):
            expanded.add(key)
    return expanded


# ── Advisory fallback for missing fix versions ────────────────────────────────
# Used when fixed_packages is empty (no errata published yet). Queries GitHub
# Advisory → OSV → NVD in sequence to find the minimum fixed version so the
# installed RPM version can be compared against it.

_advisory_fix_cache: dict[str, str | None] = {}  # cve_id → fix version or None


def _gh_ghsa_id(cve_id: str) -> str | None:
    """Return the GHSA ID for a CVE via `gh api`, or None."""
    try:
        result = subprocess.run(
            ["gh", "api", f"/advisories?cve_id={cve_id}"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if data:
                return data[0].get("ghsa_id")
    except Exception:
        pass
    return None


def _warn_if_gh_unavailable() -> None:
    try:
        result = subprocess.run(["gh", "auth", "status"], capture_output=True, timeout=5)
        if result.returncode != 0:
            log(
                "Warning: `gh` CLI is installed but not authenticated. "
                "CVEs without errata data will have fewer fix-version lookups. "
                "Run `gh auth login` to enable GitHub Advisory enrichment."
            )
    except FileNotFoundError:
        log(
            "Warning: `gh` CLI not found. CVEs without errata data will have fewer "
            "fix-version lookups. Install gh (https://cli.github.com) and run "
            "`gh auth login` to enable GitHub Advisory enrichment."
        )
    except subprocess.TimeoutExpired:
        log(
            "Warning: `gh` CLI timed out during auth check. "
            "CVEs without errata data will have fewer fix-version lookups. "
            "Run `gh auth login` to enable GitHub Advisory enrichment."
        )


_OSV_ALIAS_RE = re.compile(r'aliases were: ([A-Z]+-\d+-\d+)')


def _osv_fix_version(initial_ids: list, installed_version: str) -> str | None:
    """Return the fix version from OSV, trying multiple IDs and following alias hints.

    OSV may 404 on a GHSA ID but return an error body like:
      {"message":"Bug not found, but the following aliases were: PYSEC-2026-196"}
    We parse that alias and retry automatically. Accepts a list of IDs to try
    in order (e.g. [cve_id, ghsa_id]) so we cast the widest net first.
    """
    queue = list(initial_ids)
    seen: set[str] = set()

    while queue:
        osv_id = queue.pop(0)
        if osv_id in seen:
            continue
        seen.add(osv_id)
        try:
            url = f"https://api.osv.dev/v1/vulns/{osv_id}"
            req = urllib.request.Request(url, headers={"User-Agent": "discovery-cve-check/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                osv = json.loads(resp.read())
            fix = _best_fix_from_events(osv, installed_version)
            if fix:
                return fix
        except urllib.error.HTTPError as e:
            # OSV 404 bodies often name the correct alias — follow it
            try:
                body = e.read().decode()
                m = _OSV_ALIAS_RE.search(body)
                if m and m.group(1) not in seen:
                    queue.append(m.group(1))
            except Exception:
                pass
        except Exception:
            pass

    return None


def _nvd_fix_version(cve_id: str, installed_version: str) -> str | None:
    """Return the fix version from NVD CPE data for a CVE, or None."""
    try:
        url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
        req = urllib.request.Request(url, headers={"User-Agent": "discovery-cve-check/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except Exception:
        return None

    best_fix: str | None = None
    best_start: str = "0"

    for item in data.get("vulnerabilities", []):
        for cfg in item.get("cve", {}).get("configurations", []):
            for node in cfg.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    if not cpe.get("vulnerable"):
                        continue
                    end_excl = cpe.get("versionEndExcluding")
                    if not end_excl:
                        continue
                    start = cpe.get("versionStartIncluding") or "0"
                    # Range applies if installed >= start (highest matching start wins)
                    if evr_gte(installed_version, start):
                        if best_fix is None or evr_gte(start, best_start):
                            best_fix = end_excl
                            best_start = start

    return best_fix


def _best_fix_from_events(osv: dict, installed_version: str) -> str | None:
    """Extract the applicable fix version from OSV ECOSYSTEM range events."""
    best_fix: str | None = None
    best_start: str = "0"
    for aff in osv.get("affected", []):
        for r in aff.get("ranges", []):
            if r.get("type") != "ECOSYSTEM":
                continue
            introduced = "0"
            for ev in r.get("events", []):
                if "introduced" in ev:
                    introduced = ev["introduced"]
                elif "fixed" in ev:
                    fix = ev["fixed"]
                    if evr_gte(installed_version, introduced):
                        if best_fix is None or evr_gte(introduced, best_start):
                            best_fix = fix
                            best_start = introduced
    return best_fix


def _advisory_fix_version(cve_id: str, installed_version: str) -> str | None:
    """Last-resort fix-version lookup: GitHub Advisory → OSV → NVD.

    Called only when fixed_packages is empty and packages were found in the
    container. Returns a semver fix version (e.g. '26.1.2') that can be
    compared directly against the RPM version number.
    """
    cache_key = f"{cve_id}:{installed_version}"
    if cache_key in _advisory_fix_cache:
        return _advisory_fix_cache[cache_key]

    fix: str | None = None

    # 1 — OSV: try both the CVE ID and the GHSA ID (if we can get it).
    # OSV 404 responses include alias hints, so we follow them automatically.
    # Starting with the CVE ID catches cases where GHSA 404s but PYSEC records exist.
    osv_ids: list[str] = [cve_id]
    ghsa_id = _gh_ghsa_id(cve_id)
    if ghsa_id:
        osv_ids.append(ghsa_id)
    fix = _osv_fix_version(osv_ids, installed_version)

    # 2 — NVD: final fallback when OSV has no ECOSYSTEM ranges for any alias
    if fix is None:
        fix = _nvd_fix_version(cve_id, installed_version)

    _advisory_fix_cache[cache_key] = fix
    return fix


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


def image_url(checked_images: dict, container: str) -> str | None:
    """Extract image URL from checked_images entry (supports both old str and new dict format)."""
    entry = checked_images.get(container)
    if isinstance(entry, dict):
        return entry.get("image")
    return entry


_warn_if_gh_unavailable()
log("Loading input files...")

unified = load_json("cve-data/unified-cves.json", "unified-cves.json")
checked_images = load_json(f"cve-data/checked-images-{set_name}.json", "checked-images.json")

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
        log(f"  Skipping {container}: not in checked-images-{set_name}.json (was not pulled)")


# ── Module stream NVR detection ───────────────────────────────────────────────

_MODULE_STREAM_RELEASE_RE = re.compile(r'^\d{10,}(\.\d+)?$')


def _is_module_stream_nvr(nvr: str) -> bool:
    """Return True if nvr belongs to an RHEL Application Stream module stream.

    Module stream NVRs (e.g. 'nginx-1.24-9080020260610161820.9') carry a release
    component that is a large integer timestamp (YYYYMMDDHHMMSS, 13-19 digits)
    optionally followed by '.N'.  These identify the module stream metadata package,
    not the binary RPM installed in the container, so version comparison against
    an installed binary NVR is meaningless and must be skipped.
    """
    evr = parse_evr(nvr)
    return bool(_MODULE_STREAM_RELEASE_RE.match(evr[2]))


# ── Check each CVE against container RPM lists ───────────────────────────────

def check_cve_in_container(cve: dict, container: str) -> dict:
    """
    Return a checked_containers entry for one CVE + container combination.
    """
    result = {
        "checked_image": image_url(checked_images, container),
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
    module_stream_skipped: list[str] = []
    for fp in cve.get("fixed_packages", []):
        name = package_name_from_entry(fp)
        nvr  = fp.get("nvr")
        if name and nvr:
            if _is_module_stream_nvr(nvr):
                module_stream_skipped.append(nvr)
                continue
            if name not in fixed_by_name or parse_evr(nvr) < parse_evr(fixed_by_name[name]):
                fixed_by_name[name] = nvr
    if module_stream_skipped:
        log(f"  {cve['cve_id']}: skipped {len(module_stream_skipped)} module stream fix NVR(s) "
            f"({', '.join(module_stream_skipped)}) — not comparable to binary package versions")

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

    if not search_names:
        return result

    container_index = rpm_index.get(container, {})

    # searched_names records the logical/canonical names from the CVE data.
    # This is what flows into package_names in the comparison report and into
    # find-unknown-packages.py — it should not include binary RPM expansion names.
    result["searched_names"] = sorted(search_names)

    # Expand 'python-X' source package names to include binary RPM variants
    # (python3-X, python3.12-X, python3.12-X-wheel, etc.) present in the index.
    # This expansion is an internal search detail and is NOT written to searched_names.
    effective_names: set[str] = set()
    for name in search_names:
        effective_names.update(_expand_python_names(name, container_index))

    found_nvras: list[str] = []
    relevant_fixed_nvr: str | None = None

    for name in effective_names:
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

    # Last-resort: if packages found but no minimum fixed NVR (no errata yet),
    # query GitHub Advisory → OSV → NVD for a fix version.
    if relevant_fixed_nvr is None:
        # Extract installed version from the first found NVRA for range matching
        installed_ver: str | None = None
        for name in effective_names:
            for m in container_index.get(name, []):
                installed_ver = m["version"]
                break
            if installed_ver:
                break
        if installed_ver:
            adv_fix = _advisory_fix_version(cve["cve_id"], installed_ver)
            if adv_fix:
                log(f"  {cve['cve_id']}: fix version {adv_fix!r} from advisory "
                    f"(no errata NVR available)")
                relevant_fixed_nvr = adv_fix
                result["minimum_fixed_nvr"] = adv_fix

    if relevant_fixed_nvr is None:
        return result  # is_fixed stays None — fix version unknown

    # is_fixed = True only if ALL matching packages are at or above the fixed version.
    # Use effective_names (expanded set) so binary RPM variants are all checked.
    all_fixed = all(
        evr_gte(f"{m['version']}-{m['release']}", relevant_fixed_nvr)
        for name in effective_names
        for m in container_index.get(name, [])
    )
    result["is_fixed"] = all_fixed
    return result


log(f"\nChecking {len(unified['cves'])} CVEs against container RPM lists...")
t0 = time.time()

enriched_cves = []
stats = {c: {"found": 0, "fixed": 0, "not_fixed": 0, "unknown": 0, "not_found": 0, "no_package_data": 0}
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
        else:
            # CVE affects this container but we have no RPM package data to search
            # (may be a non-RPM dependency such as npm or Python package)
            s["no_package_data"] += 1

    cve_out["checked_containers"] = checked_containers
    enriched_cves.append(cve_out)

log(f"Checked {len(enriched_cves)} CVEs in {time.time() - t0:.1f}s.")


# ── Build output ──────────────────────────────────────────────────────────────

output = {
    "generated_at": unified.get("generated_at"),
    "verified_at": datetime.now(timezone.utc).isoformat(),
    "build_info": {
        "containers": dict(checked_images),
        "source": None,
    },
    "verification": {
        "images": dict(checked_images),
        "skipped_nvras": skipped_nvras,
    },
    "summary": unified.get("summary", {}),
    "verification_summary": {
        container: {
            "checked_image": image_url(checked_images, container),
            **s,
        }
        for container, s in stats.items()
    },
    "cves": enriched_cves,
}

with open(f"cve-data/verified-cves-{set_name}.json", "w") as f:
    json.dump(output, f, indent=2)

log(f"\nWrote cve-data/verified-cves-{set_name}.json ({len(enriched_cves)} CVEs)")
