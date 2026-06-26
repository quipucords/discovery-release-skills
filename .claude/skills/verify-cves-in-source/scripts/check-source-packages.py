#!/usr/bin/env python3
"""Check CVE fix status against source code repository lockfiles.

For CVEs where RPM scanning returned is_fixed=None (non-RPM packages such as
npm or pip), this script checks the upstream source repos to determine whether
the installed version meets or exceeds the minimum fixed version from JIRA.

Reads:
  cve-data/unified-cves.json         — CVE records with advisory notes
  QUIPUCORDS_SERVER_REPO_PATH env    — path to quipucords server repo
  QUIPUCORDS_UI_REPO_PATH env        — path to quipucords-ui repo

Writes:
  cve-data/verified-cves-source.json — per-CVE source check results

All progress messages go to stderr. Exits non-zero on failure.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

# ── Container / repo configuration ───────────────────────────────────────────

SERVER_CONTAINER = os.environ.get(
    "DOWNSTREAM_SERVER_IMAGE",
    "registry.redhat.io/discovery/discovery-server-rhel9",
).split("/", 1)[1]

UI_CONTAINER = os.environ.get(
    "DOWNSTREAM_UI_IMAGE",
    "registry.redhat.io/discovery/discovery-ui-rhel9",
).split("/", 1)[1]

SERVER_REPO_PATH = os.environ.get("QUIPUCORDS_SERVER_REPO_PATH", "../quipucords")
UI_REPO_PATH     = os.environ.get("QUIPUCORDS_UI_REPO_PATH",     "../quipucords-ui")
SERVER_REPO_URL  = os.environ.get("QUIPUCORDS_SERVER_REPO_URL",  "git@github.com:quipucords/quipucords.git")
UI_REPO_URL      = os.environ.get("QUIPUCORDS_UI_REPO_URL",      "git@github.com:quipucords/quipucords-ui.git")

# container → (repo_path, repo_url, ecosystem)
CONTAINER_REPO_MAP = {
    SERVER_CONTAINER: (SERVER_REPO_PATH, SERVER_REPO_URL, "pip"),
    UI_CONTAINER:     (UI_REPO_PATH,     UI_REPO_URL,     "npm"),
}

def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ── Git helpers ───────────────────────────────────────────────────────────────

def _git(repo_path: str, *cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["git", "-C", repo_path, *cmd],
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        log(f"  git {' '.join(cmd)} failed in {repo_path}:")
        log(f"  {result.stderr.strip()}")
        sys.exit(1)
    return result


def _resolve_sha(repo_path: str) -> str:
    return _git(repo_path, "rev-parse", "HEAD").stdout.strip()


def _ensure_repo(repo_path: str, repo_url: str, commitish: str, yes: bool = False) -> str:
    """Clone if missing, fetch, check for dirty files, checkout commitish. Returns SHA."""
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        log(f"  Repo not found at {repo_path!r} — cloning from {repo_url}")
        result = subprocess.run(
            ["git", "clone", repo_url, repo_path],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            log(f"Error: git clone failed:\n{result.stderr.strip()}")
            sys.exit(1)
        log(f"  Cloned OK.")
    else:
        log(f"  Fetching latest from origin in {repo_path!r}")
        _git(repo_path, "fetch", "--tags", "origin")

    # Check for uncommitted changes.
    # Untracked files (lines starting "??") cannot affect lockfile reads — no prompt needed.
    # Modified tracked lockfiles are the only case that can corrupt results.
    status_lines = _git(repo_path, "status", "--porcelain").stdout.splitlines()
    tracked_modified = [l for l in status_lines if l and not l.startswith("??")]
    untracked_only   = [l for l in status_lines if l and l.startswith("??")]

    if untracked_only and not tracked_modified:
        log(f"  Note: {repo_path!r} has {len(untracked_only)} untracked file(s) "
            f"(ignored — lockfiles are unaffected).")

    if tracked_modified:
        log(f"\n  Warning: {repo_path!r} has {len(tracked_modified)} tracked file(s) with uncommitted changes:")
        for line in tracked_modified[:15]:
            log(f"    {line}")

        dirty_lockfiles = [
            lf for lf in (
                "lockfiles/requirements.txt",
                "lockfiles/requirements-build.txt",
                "package-lock.json",
                "package.json",
                "uv.lock",
            )
            if any(lf in line for line in tracked_modified)
        ]
        if dirty_lockfiles:
            log(f"\n  !! LOCKFILE(S) HAVE UNCOMMITTED CHANGES: {dirty_lockfiles}")
            log("  !! Version data may not reflect the committed state at this commitish.")

        if yes:
            log("  Continuing anyway (--yes).")
        else:
            try:
                answer = input(f"\n  Continue with {repo_path!r} despite uncommitted changes? [y/N] ")
            except EOFError:
                answer = "n"
            if answer.strip().lower() not in ("y", "yes"):
                log("Aborted.")
                sys.exit(1)

    log(f"  Checking out {commitish!r}")
    _git(repo_path, "checkout", commitish)
    sha = _resolve_sha(repo_path)
    log(f"  HEAD → {sha[:12]}")
    return sha


# ── Package name normalization ────────────────────────────────────────────────

def _normalize_pip(name: str) -> str:
    """PEP 503: lowercase, collapse [-_.]+ to a single hyphen."""
    return re.sub(r"[-_.]+", "-", name.lower())


def _normalize_npm(name: str) -> str:
    return name.lower()


# ── Version comparison ────────────────────────────────────────────────────────

def _parse_version(v: str) -> tuple:
    """Parse a dotted version string into a comparable tuple of (int, str) pairs.

    Trailing punctuation is stripped. Pre-release suffixes (e.g. "1.0.0a1") sort
    below the same numeric-only version because the suffix str sorts < "".
    """
    v = v.rstrip(".,;: ")
    parts = []
    for segment in v.split("."):
        m = re.match(r"^(\d+)(.*)", segment)
        if m:
            parts.append((int(m.group(1)), m.group(2)))
        else:
            parts.append((0, segment))
    return tuple(parts)


def version_gte(installed: str, fixed: str) -> bool:
    """Return True if installed >= fixed by dotted-version comparison."""
    try:
        return _parse_version(installed) >= _parse_version(fixed)
    except Exception:
        return False


# ── Lockfile readers ──────────────────────────────────────────────────────────

# Matches "package==version [; conditions]" lines in requirements.txt.
# Handles extras like "package[extra]==version" — extras are stripped.
_REQ_RE = re.compile(r"^([A-Za-z0-9][\w.\-]*(?:\[[^\]]*\])?)==([^\s;]+)")


def _parse_requirements_file(path: str, index: dict) -> None:
    """Parse a pip requirements.txt lockfile into index (normalized_name → version)."""
    with open(path) as f:
        for line in f:
            stripped = line.rstrip()
            if not stripped or stripped.startswith("#") or stripped[0].isspace():
                continue
            m = _REQ_RE.match(stripped)
            if m:
                raw_name = m.group(1)
                base_name = re.sub(r"\[.*?\]", "", raw_name)
                index[_normalize_pip(base_name)] = m.group(2)


def _read_pip_lockfile(repo_path: str) -> tuple[dict, str | None]:
    """Read lockfiles/requirements.txt and lockfiles/requirements-build.txt.

    Both files are authoritative sources for what ends up in container images:
    requirements.txt is installed directly (COPY + pip install -r), and
    requirements-build.txt covers transitive build-time dependencies that
    Red Hat's hermetic build system tracks. uv.lock is intentionally ignored
    since it is not used in the container build process.

    Returns ({normalized_name: version}, comma-joined lockfile paths).
    """
    index: dict[str, str] = {}
    found_paths: list[str] = []

    for filename in ("requirements.txt", "requirements-build.txt"):
        path = os.path.join(repo_path, "lockfiles", filename)
        if os.path.isfile(path):
            log(f"    Reading {path}")
            _parse_requirements_file(path, index)
            found_paths.append(os.path.relpath(path, repo_path))

    if not found_paths:
        log(f"  Warning: No pip lockfile found in {repo_path!r}")
        return {}, None

    return index, ", ".join(found_paths)


def _read_npm_lockfile(repo_path: str) -> tuple[dict, str | None]:
    """Read package-lock.json (v2/v3 format).

    Returns ({normalized_name: version}, relative_lockfile_path).
    Prefers direct (non-nested) node_modules entries over nested ones.
    """
    lock_path = os.path.join(repo_path, "package-lock.json")
    if not os.path.isfile(lock_path):
        log(f"  Warning: package-lock.json not found in {repo_path!r}")
        return {}, None

    log(f"    Reading {lock_path}")
    with open(lock_path) as f:
        data = json.load(f)

    packages = data.get("packages", {})
    index: dict[str, str] = {}
    # Direct entries have exactly one "node_modules/" segment in their key.
    # Track whether we've set a direct entry to avoid clobbering it with a nested one.
    direct: set[str] = set()

    for key, entry in packages.items():
        if not key:
            continue  # skip the root "" entry
        parts = key.split("node_modules/")
        if len(parts) < 2:
            continue
        pkg_name = parts[-1]  # last segment is the package name (handles scopes too)
        version = entry.get("version", "")
        if not version:
            continue
        norm = _normalize_npm(pkg_name)
        is_direct = len(parts) == 2
        if norm not in index or is_direct:
            index[norm] = version
            if is_direct:
                direct.add(norm)

    return index, os.path.relpath(lock_path, repo_path)


# ── GitHub Advisory Database lookup ──────────────────────────────────────────

_advisory_cache: dict[str, list] = {}


def _fetch_github_advisory(cve_id: str) -> list:
    """Query GitHub Advisory Database for a CVE via `gh api`. Returns advisory list."""
    if cve_id in _advisory_cache:
        return _advisory_cache[cve_id]
    try:
        result = subprocess.run(
            ["gh", "api", f"/advisories?cve_id={cve_id}"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            advisories = json.loads(result.stdout)
            _advisory_cache[cve_id] = advisories
            return advisories
    except FileNotFoundError:
        log("  Warning: `gh` CLI not found — skipping GitHub Advisory lookup.")
    except subprocess.TimeoutExpired:
        log(f"  Warning: GitHub Advisory lookup timed out for {cve_id}.")
    except json.JSONDecodeError:
        pass
    _advisory_cache[cve_id] = []
    return []


# Maps our internal ecosystem names to the names OSV uses.
_OSV_ECOSYSTEM = {"pip": "pypi", "npm": "npm", "gem": "rubygems", "go": "go", "maven": "maven"}

_osv_cache: dict[str, dict] = {}


_OSV_ALIAS_RE = re.compile(r'aliases were: ([A-Z]+-\d+-\d+)')


def _fetch_osv_advisory(osv_id: str) -> dict:
    """Fetch OSV.dev data for an ID (GHSA, CVE, PYSEC, etc.) via HTTPS.

    OSV aggregates PyPI, npm, Go, Maven, and other ecosystem advisories.
    When a lookup 404s, the error body often names the canonical alias
    (e.g. 'PYSEC-2026-196') — we follow it automatically so callers don't
    need to know the OSV-internal ID up front.

    Returns the OSV vulnerability object, or {} on failure.
    """
    queue = [osv_id]
    seen: set[str] = set()

    while queue:
        cur_id = queue.pop(0)
        if cur_id in seen:
            continue
        seen.add(cur_id)
        if cur_id in _osv_cache:
            return _osv_cache[cur_id]
        try:
            url = f"https://api.osv.dev/v1/vulns/{cur_id}"
            req = urllib.request.Request(url, headers={"User-Agent": "discovery-cve-check/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            _osv_cache[osv_id] = data
            _osv_cache[cur_id] = data
            return data
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode()
                m = _OSV_ALIAS_RE.search(body)
                if m and m.group(1) not in seen:
                    queue.append(m.group(1))
            except Exception:
                pass
        except Exception:
            pass

    _osv_cache[osv_id] = {}
    return {}


def _osv_eco(ecosystem: str) -> str:
    """Normalize internal ecosystem name to the name OSV uses (e.g. 'pip' → 'pypi')."""
    return _OSV_ECOSYSTEM.get(ecosystem.lower(), ecosystem.lower())


def _osv_fixed_version(osv_data: dict, ecosystem: str, pkg_name: str, installed_version: str) -> str | None:
    """Extract the applicable fixed version from OSV ECOSYSTEM ranges.

    OSV uses ECOSYSTEM ranges with event lists: [{"introduced":"0"}, {"fixed":"26.1.2"}].
    Finds the range series whose lower bound is satisfied by installed_version
    (highest matching lower bound), then returns the corresponding fixed version.
    """
    normalize = _normalize_npm if ecosystem == "npm" else _normalize_pip
    norm_target = normalize(pkg_name)
    osv_ecosystem = _osv_eco(ecosystem)
    v_installed = _parse_version(installed_version)

    best_fixed: str | None = None
    best_lower: tuple | None = None

    for aff in osv_data.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem", "").lower() != osv_ecosystem:
            continue
        if normalize(pkg.get("name", "")) != norm_target:
            continue
        for r in aff.get("ranges", []):
            if r.get("type") != "ECOSYSTEM":
                continue
            introduced = _parse_version("0")
            for ev in r.get("events", []):
                if "introduced" in ev:
                    introduced = _parse_version(ev["introduced"])
                elif "fixed" in ev:
                    fixed_ver = ev["fixed"]
                    if v_installed >= introduced:
                        if best_lower is None or introduced > best_lower:
                            best_fixed = fixed_ver
                            best_lower = introduced

    return best_fixed


def version_in_range(version: str, version_range: str) -> bool:
    """Return True if version satisfies all conditions in a GHSA version range string.

    Range examples (comma-separated conditions):
      "<= 3.1.1"
      ">= 1.1.0, <= 1.8.3"
      ">= 8.0.0, < 8.21.0"
    """
    v = _parse_version(version)
    for cond in version_range.split(","):
        cond = cond.strip()
        if cond.startswith(">="):
            if v < _parse_version(cond[2:].strip()): return False
        elif cond.startswith(">"):
            if v <= _parse_version(cond[1:].strip()): return False
        elif cond.startswith("<="):
            if v > _parse_version(cond[2:].strip()): return False
        elif cond.startswith("<"):
            if v >= _parse_version(cond[1:].strip()): return False
        elif cond.startswith("="):
            if v != _parse_version(cond[1:].strip()): return False
    return True


def _get_advisory_fixed_version(
    cve_id: str,
    ecosystem: str,
    pkg_name: str,
    installed_version: str,
) -> tuple[str | None, str | None, str | None, bool]:
    """Return (first_patched_version, ghsa_id, osv_canonical_name, below_all_ranges).

    Queries in order:
    1. GitHub Advisory Database (via `gh api`) — fast, good for npm/general
    2. OSV.dev (via HTTPS, stdlib urllib) — broader coverage; provides canonical
       ecosystem package names that may differ from JIRA names (e.g. "pip" vs
       "python-pip"), and version ranges for advisories GitHub marks as unreviewed.

    The returned osv_canonical_name is the OSV-authoritative package name for the
    given ecosystem. Callers should retry the lockfile lookup with this name if
    the original JIRA-derived name failed to match.

    below_all_ranges is True when GHSA has ranges for this package/ecosystem but the
    installed version falls below all of them (i.e., predates the documented
    vulnerability). GHSA reviewed advisories are authoritative for this determination.
    """
    # First, get the GHSA ID from the advisory — even if it has no version ranges.
    advisories = _fetch_github_advisory(cve_id)
    ghsa_id: str | None = advisories[0].get("ghsa_id") if advisories else None

    # Try GHSA structured version ranges.
    fixed_ver, _, ghsa_below_range = _get_ghsa_fixed_version(cve_id, ecosystem, pkg_name, installed_version)

    # GHSA reviewed advisories are authoritative: if the version predates all documented
    # vulnerable ranges, return early without querying OSV or NVD.
    if ghsa_below_range:
        return None, ghsa_id, None, True

    # Fetch OSV data for canonical package name and (if needed) version ranges.
    osv_canonical: str | None = None
    if ghsa_id:
        osv = _fetch_osv_advisory(ghsa_id) or _fetch_osv_advisory(cve_id)
        if osv:
            # Extract canonical package name for this ecosystem from OSV
            osv_ecosystem = _osv_eco(ecosystem)
            for aff in osv.get("affected", []):
                pkg = aff.get("package", {})
                if pkg.get("ecosystem", "").lower() == osv_ecosystem:
                    osv_canonical = pkg.get("name")
                    break
            # If GHSA gave no fix version, try OSV version ranges
            if fixed_ver is None and osv_canonical:
                fixed_ver = _osv_fixed_version(osv, ecosystem, osv_canonical, installed_version)
                if fixed_ver:
                    log(f"    → fix version {fixed_ver!r} from OSV ({ghsa_id})")

    # 3 — NVD: final fallback when OSV also has no data or 404s on the GHSA
    if fixed_ver is None and installed_version != "0":
        fixed_ver = _nvd_fixed_version(cve_id, installed_version)
        if fixed_ver:
            log(f"    → fix version {fixed_ver!r} from NVD for {cve_id}")

    return fixed_ver, ghsa_id, osv_canonical, False


def _nvd_fixed_version(cve_id: str, installed_version: str) -> str | None:
    """Query NVD CPE data for the applicable fix version, or None.

    Finds the CPE range whose lower bound is satisfied by installed_version
    (highest matching start), returns versionEndExcluding for that range.
    """
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
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
                    if version_gte(installed_version, start):
                        if best_fix is None or version_gte(start, best_start):
                            best_fix = end_excl
                            best_start = start

    return best_fix


# Keep old name as an internal implementation — _get_advisory_fixed_version wraps it.
def _get_ghsa_fixed_version(
    cve_id: str,
    ecosystem: str,
    pkg_name: str,
    installed_version: str,
) -> tuple[str | None, str | None, bool]:
    """Return (first_patched_version, ghsa_id, below_all_ranges) from GitHub Advisory Database.

    For multi-range advisories (e.g. ws has separate ranges for 5.x, 6.x, 7.x, 8.x),
    finds the range whose version *series* the installed version belongs to — that is,
    the range whose lower bound is satisfied by installed_version, picking the most
    specific match (highest lower bound). Returns (first_patched_version, ghsa_id, False).

    This approach works whether the package is vulnerable (version in range) or already
    fixed (version >= first_patched_version): in both cases the applicable series range
    is found via its lower bound, and the caller uses version_gte() to determine status.

    When matching package/ecosystem ranges exist but the installed version is below ALL
    of their lower bounds, the version predates the documented vulnerability.
    Returns (None, ghsa_id, True) in that case.

    Returns (None, None, False) if no matching advisory or no applicable range is found.
    """
    advisories = _fetch_github_advisory(cve_id)
    normalize = _normalize_npm if ecosystem == "npm" else _normalize_pip
    norm_pkg = normalize(pkg_name)
    v_installed = _parse_version(installed_version)

    for advisory in advisories:
        ghsa_id = advisory.get("ghsa_id", "")

        best_vuln: dict | None = None
        best_lower: tuple | None = None
        all_lower_bounds: list[tuple] = []

        for vuln in advisory.get("vulnerabilities", []):
            pkg = vuln.get("package", {})
            if pkg.get("ecosystem", "").lower() != ecosystem.lower():
                continue
            if normalize(pkg.get("name", "")) != norm_pkg:
                continue
            patched = vuln.get("first_patched_version")
            if not patched:
                continue

            # Extract the lower bound of this range (>= X or > X condition).
            ver_range = vuln.get("vulnerable_version_range", "")
            lower: tuple = _parse_version("0")  # default: range starts at 0
            for cond in ver_range.split(","):
                cond = cond.strip()
                if cond.startswith(">="):
                    lower = _parse_version(cond[2:].strip())
                elif cond.startswith(">"):
                    lower = _parse_version(cond[1:].strip())

            all_lower_bounds.append(lower)

            # This range's series applies to installed_version when the lower
            # bound is satisfied (installed >= lower bound of the series).
            if v_installed >= lower:
                # Among all applicable ranges, pick the most specific (highest lower bound).
                if best_lower is None or lower > best_lower:
                    best_vuln = vuln
                    best_lower = lower

        if best_vuln:
            return best_vuln["first_patched_version"], ghsa_id, False

        # Matching package/ecosystem ranges exist but none covers installed_version.
        # If all lower bounds are above the installed version, the version predates
        # the documented vulnerability (e.g. image-size 0.5.5 vs. ranges >= 1.1.0).
        if all_lower_bounds and all(v_installed < lb for lb in all_lower_bounds):
            return None, ghsa_id, True

    return None, None, False


# ── Note parsing ──────────────────────────────────────────────────────────────

_JIRA_PKG_RE = re.compile(r"Package name from JIRA:\s+'([^']+)'")
_JIRA_VER_RE = re.compile(r"Upstream fixed version from JIRA:\s+([^\s(]+)")


def _extract_jira_hints(notes: list) -> tuple[str | None, str | None]:
    """Return (package_name, fixed_version) from CVE notes, or (None, None)."""
    pkg_name = None
    fixed_ver = None
    for note in notes:
        m = _JIRA_PKG_RE.search(note)
        if m:
            pkg_name = m.group(1)
        m = _JIRA_VER_RE.search(note)
        if m:
            fixed_ver = m.group(1).rstrip(".,;: ")
    return pkg_name, fixed_ver


# ── Per-CVE source check ──────────────────────────────────────────────────────

def check_cve_in_source(
    cve: dict,
    container: str,
    pkg_index: dict,
    lockfile: str | None,
    ecosystem: str,
) -> dict:
    """Check one CVE against a source package index for one container.

    When a fixed version is unknown (advisory not yet published), the package is still
    looked up so we can confirm presence and report the installed version. is_fixed will
    be None in that case — the delta stays 'unknown' but the version appears in the report.
    """
    result: dict = {
        "check_type": "source",
        "lockfile": lockfile,
        "package_found": False,
        "package_name": None,
        "installed_version": None,
        "minimum_fixed_version": None,
        "is_fixed": None,
    }

    if not pkg_index or not lockfile:
        return result

    pkg_name, fixed_ver = _extract_jira_hints(cve.get("notes", []))
    if not pkg_name:
        return result  # no package name at all — nothing to look up

    result["minimum_fixed_version"] = fixed_ver  # may be None if no advisory yet
    result["package_name"] = pkg_name

    # Fetch advisory data early so we have the OSV canonical name for the lookup.
    # This handles cases where the JIRA name (e.g. "python-pip") differs from the
    # lockfile name (e.g. "pip") — OSV provides the authoritative ecosystem name.
    adv_fixed: str | None = None
    ghsa_id: str | None = None
    osv_canonical: str | None = None
    if fixed_ver is None:
        adv_fixed, ghsa_id, osv_canonical, _ = _get_advisory_fixed_version(
            cve["cve_id"], ecosystem, pkg_name, "0",  # dummy version — we need canonical name
        )

    # Try the JIRA name first, then the OSV canonical name, then prefix-stripped variants.
    installed_version, matched_name = _lookup_in_index(
        pkg_name, pkg_name, osv_canonical, pkg_index, ecosystem,
    )

    # For npm: also try matching the last component of scoped package keys
    if installed_version is None and ecosystem == "npm":
        normalize = _normalize_npm
        search_key = normalize(pkg_name)
        for key, ver in pkg_index.items():
            if key.endswith("/" + search_key):
                installed_version = ver
                matched_name = pkg_name
                break

    if installed_version is None:
        if osv_canonical:
            result["package_name"] = f"{pkg_name} (OSV canonical: {osv_canonical})"
        return result

    result["package_found"] = True
    result["installed_version"] = installed_version
    if matched_name and matched_name != pkg_name:
        result["package_name"] = matched_name  # report the name that actually matched

    # Now re-run advisory lookup with the real installed version for accurate range matching.
    if fixed_ver is None:
        lookup_name = osv_canonical or pkg_name
        adv_fixed, ghsa_id, _, below_range = _get_advisory_fixed_version(
            cve["cve_id"], ecosystem, lookup_name, installed_version,
        )
        if adv_fixed:
            log(f"    {cve['cve_id']}: found fix version {adv_fixed!r} via {ghsa_id}")
            fixed_ver = adv_fixed
            result["minimum_fixed_version"] = adv_fixed
            result["ghsa_source"] = ghsa_id
        elif below_range:
            log(f"    {cve['cve_id']}: v{installed_version} is below all documented "
                f"vulnerable ranges in {ghsa_id} — treating as not affected")
            result["is_fixed"] = True
            result["ghsa_source"] = ghsa_id
            result["minimum_fixed_version"] = "(below documented vulnerable range)"

    if fixed_ver is not None:
        result["is_fixed"] = version_gte(installed_version, fixed_ver)
    # else: is_fixed stays None — package found but no fix version available anywhere
    return result


def _lookup_in_index(pkg_name: str, jira_name: str | None, osv_canonical: str | None,
                     pkg_index: dict, ecosystem: str) -> tuple[str | None, str | None]:
    """Search a package index using candidate names, returning (version, matched_name).

    Tries in order: JIRA name, OSV canonical name. For pip, also strips
    common RHEL source-package prefixes (python-, python3-, python3.X-) that
    appear in JIRA NVRs but not in lockfile entries.
    """
    normalize = _normalize_npm if ecosystem == "npm" else _normalize_pip

    candidates: list[str] = []
    for name in (jira_name, osv_canonical):
        if name:
            candidates.append(name)
            if ecosystem == "pip":
                # Strip RHEL source-package prefixes: python-X → X, python3-X → X, etc.
                stripped = re.sub(r"^python\d*(?:\.\d+)?-", "", normalize(name))
                if stripped != normalize(name):
                    candidates.append(stripped)

    seen: set[str] = set()
    for name in candidates:
        key = normalize(name)
        if key in seen:
            continue
        seen.add(key)
        ver = pkg_index.get(key)
        if ver is not None:
            return ver, name

    return None, None


# ── Main ──────────────────────────────────────────────────────────────────────

def _prompt_commitish(label: str, repo_path: str) -> str:
    """Interactively prompt for a commitish when one was not supplied via CLI."""
    try:
        answer = input(f"Enter commitish for {label} ({repo_path!r}) [tag/branch/SHA]: ").strip()
    except EOFError:
        answer = ""
    return answer or "main"


if __name__ == "__main__":
    _parser = argparse.ArgumentParser(
        description="Check CVE fix status against source repo lockfiles.")
    _parser.add_argument("--server-commitish", default=None, metavar="COMMITISH",
                         help="Tag, branch, or SHA to check in the server repo")
    _parser.add_argument("--ui-commitish", default=None, metavar="COMMITISH",
                         help="Tag, branch, or SHA to check in the UI repo")
    _parser.add_argument("--yes", "-y", action="store_true",
                         help="Skip confirmation prompts for repos with uncommitted changes")
    _args = _parser.parse_args()

    log("Loading cve-data/unified-cves.json...")
    try:
        with open("cve-data/unified-cves.json") as f:
            unified = json.load(f)
    except FileNotFoundError:
        log("Error: cve-data/unified-cves.json not found. Run query-all-cves first.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        log(f"Error: cve-data/unified-cves.json is not valid JSON: {e}")
        sys.exit(1)

    # Resolve commitishes — prompt if not provided via CLI
    server_commitish = _args.server_commitish or _prompt_commitish("server repo", SERVER_REPO_PATH)
    ui_commitish     = _args.ui_commitish     or _prompt_commitish("UI repo",     UI_REPO_PATH)

    commitish_map = {
        SERVER_CONTAINER: (SERVER_REPO_PATH, SERVER_REPO_URL, server_commitish, "pip"),
        UI_CONTAINER:     (UI_REPO_PATH,     UI_REPO_URL,     ui_commitish,     "npm"),
    }

    # Set up repos and build package indices
    pkg_indices: dict[str, tuple[dict, str | None, str]] = {}
    repo_info: dict[str, dict] = {}

    for container, (repo_path, repo_url, commitish, ecosystem) in commitish_map.items():
        label = "server" if ecosystem == "pip" else "UI"
        log(f"\n[{label}] {repo_path!r} @ {commitish!r}")
        sha = _ensure_repo(repo_path, repo_url, commitish, yes=_args.yes)

        if ecosystem == "pip":
            index, lockfile = _read_pip_lockfile(repo_path)
        else:
            index, lockfile = _read_npm_lockfile(repo_path)

        pkg_indices[container] = (index, lockfile, ecosystem)
        repo_info[ecosystem] = {
            "path": repo_path,
            "commitish": commitish,
            "sha": sha,
            "lockfile": lockfile,
        }
        log(f"    Loaded {len(index)} packages from lockfile")

    # Check each CVE against source package indices
    log(f"\nChecking {len(unified['cves'])} CVEs against source lockfiles...")

    source_cves = []
    skipped_no_hints = 0

    for cve in unified["cves"]:
        pkg_name, fixed_ver = _extract_jira_hints(cve.get("notes", []))
        if not pkg_name:
            skipped_no_hints += 1
            continue

        checked_containers = {}
        for container in cve.get("affected_containers", []):
            if container not in pkg_indices:
                continue
            index, lockfile, ecosystem = pkg_indices[container]
            entry = check_cve_in_source(cve, container, index, lockfile, ecosystem)
            checked_containers[container] = entry

        if not checked_containers:
            skipped_no_hints += 1
            continue

        source_cves.append({
            "cve_id": cve["cve_id"],
            "checked_containers": checked_containers,
        })

    log(f"  {len(source_cves)} CVEs with source hints checked; "
        f"{skipped_no_hints} skipped (no JIRA package/version hints in notes)")

    # Build summary
    all_entries = [
        entry
        for cve in source_cves
        for entry in cve["checked_containers"].values()
    ]
    summary = {
        "total_checked": len(source_cves),
        "fixed_in_source": sum(1 for e in all_entries if e.get("is_fixed") is True),
        "not_fixed_in_source": sum(1 for e in all_entries if e.get("is_fixed") is False),
        "not_found": sum(1 for e in all_entries if not e.get("package_found")),
    }

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repos": repo_info,
        "summary": summary,
        "cves": source_cves,
    }

    with open("cve-data/verified-cves-source.json", "w") as f:
        json.dump(output, f, indent=2)

    log(f"\nWrote cve-data/verified-cves-source.json")
    log(f"  Total CVEs checked:  {summary['total_checked']}")
    log(f"  Fixed in source:     {summary['fixed_in_source']}")
    log(f"  Not fixed in source: {summary['not_fixed_in_source']}")
    log(f"  Package not found:   {summary['not_found']}")
