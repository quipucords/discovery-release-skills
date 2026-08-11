"""Tests for verify-cves-in-source/scripts/check-source-packages.py

Covers: version comparison, package name normalization, lockfile parsing,
and the check_cve_in_source function.
"""
import importlib.util
import json
import pathlib
import tempfile
import os


def _load():
    path = (pathlib.Path(__file__).parent.parent
            / ".claude/skills/verify-cves-in-source/scripts/check-source-packages.py")
    spec = importlib.util.spec_from_file_location("check_source_packages", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_mod = _load()
version_gte                = _mod.version_gte
_normalize_pip             = _mod._normalize_pip
_normalize_npm             = _mod._normalize_npm
_parse_version             = _mod._parse_version
_extract_jira_hints        = _mod._extract_jira_hints
_read_pip_lockfile         = _mod._read_pip_lockfile
_read_npm_lockfile         = _mod._read_npm_lockfile
check_cve_in_source        = _mod.check_cve_in_source
version_in_range           = _mod.version_in_range
_get_ghsa_fixed_version    = _mod._get_ghsa_fixed_version
_get_advisory_fixed_version = _mod._get_advisory_fixed_version
_osv_fixed_version         = _mod._osv_fixed_version
_lookup_in_index           = _mod._lookup_in_index
_advisory_cache            = _mod._advisory_cache
_osv_cache                 = _mod._osv_cache


# ── version_gte ───────────────────────────────────────────────────────────────

def test_version_gte_equal():
    assert version_gte("1.16.0", "1.16.0") is True


def test_version_gte_greater():
    assert version_gte("1.17.0", "1.16.0") is True


def test_version_gte_less():
    assert version_gte("1.15.0", "1.16.0") is False


def test_version_gte_patch_greater():
    assert version_gte("1.16.1", "1.16.0") is True


def test_version_gte_patch_less():
    assert version_gte("1.16.0", "1.16.1") is False


def test_version_gte_major_wins():
    assert version_gte("2.0.0", "1.99.99") is True


def test_version_gte_trailing_punctuation_in_fixed():
    # JIRA sometimes emits "0.32.0." with a trailing period
    assert version_gte("0.32.0", "0.32.0.") is True
    assert version_gte("0.31.9", "0.32.0.") is False


def test_version_gte_two_part():
    assert version_gte("26.1", "26.0") is True
    assert version_gte("26.0", "26.1") is False


def test_version_gte_four_part():
    assert version_gte("1.2.3.4", "1.2.3.3") is True


def test_version_gte_final_release_vs_rc():
    # 2.20.7 (final) must be >= 2.20.7rc1 — rc is a pre-release, final comes after
    assert version_gte("2.20.7", "2.20.7rc1") is True


def test_version_gte_rc_not_gte_final():
    assert version_gte("2.20.7rc1", "2.20.7") is False


def test_version_gte_final_vs_alpha():
    assert version_gte("1.0.0", "1.0.0a1") is True


def test_version_gte_final_vs_beta():
    assert version_gte("1.0.0", "1.0.0b2") is True


def test_version_gte_beta_not_gte_final():
    assert version_gte("1.0.0b2", "1.0.0") is False


def test_version_gte_rc_equal_to_same_rc():
    assert version_gte("2.20.7rc1", "2.20.7rc1") is True


def test_version_gte_rc10_greater_than_rc2():
    # Serial number must compare numerically: rc10 > rc2, not string-sorted
    assert version_gte("1.0.0rc10", "1.0.0rc2") is True
    assert version_gte("1.0.0rc2", "1.0.0rc10") is False


def test_version_gte_c_and_rc_are_equivalent():
    # PEP 440: 'c' is a legacy alias for 'rc'
    assert version_gte("1.0.0c1", "1.0.0rc1") is True
    assert version_gte("1.0.0rc1", "1.0.0c1") is True


def test_version_gte_dev_less_than_alpha():
    # PEP 440 ordering: dev < a < b < rc < final
    assert version_gte("1.0.0dev1", "1.0.0a1") is False
    assert version_gte("1.0.0a1", "1.0.0dev1") is True


# ── name normalization ────────────────────────────────────────────────────────

def test_normalize_pip_lowercase():
    assert _normalize_pip("Requests") == "requests"


def test_normalize_pip_underscores_to_hyphen():
    assert _normalize_pip("my_package") == "my-package"


def test_normalize_pip_dots_to_hyphen():
    assert _normalize_pip("zope.interface") == "zope-interface"


def test_normalize_pip_mixed():
    assert _normalize_pip("My_Package.Name") == "my-package-name"


def test_normalize_npm_lowercase():
    assert _normalize_npm("Axios") == "axios"


def test_normalize_npm_scoped():
    assert _normalize_npm("@patternfly/react-core") == "@patternfly/react-core"


# ── _extract_jira_hints ───────────────────────────────────────────────────────

def test_extract_jira_hints_standard():
    notes = [
        "Package name from JIRA: 'Axios' (upstream name; may differ from RPM name)",
        "Upstream fixed version from JIRA: 1.16.0 (semver, not an RPM NVR)",
    ]
    pkg, ver = _extract_jira_hints(notes)
    assert pkg == "Axios"
    assert ver == "1.16.0"


def test_extract_jira_hints_trailing_period():
    notes = ["Upstream fixed version from JIRA: 0.32.0. (semver, not an RPM NVR)"]
    _, ver = _extract_jira_hints(notes)
    assert ver == "0.32.0"


def test_extract_jira_hints_no_notes():
    assert _extract_jira_hints([]) == (None, None)


def test_extract_jira_hints_missing_version():
    notes = ["Package name from JIRA: 'axios'"]
    pkg, ver = _extract_jira_hints(notes)
    assert pkg == "axios"
    assert ver is None


def test_extract_jira_hints_missing_package():
    notes = ["Upstream fixed version from JIRA: 1.0.0"]
    pkg, ver = _extract_jira_hints(notes)
    assert pkg is None
    assert ver == "1.0.0"


def test_extract_jira_hints_reads_osv_sourced_package_note():
    # Notes written by enrich_package_names_from_osv use "from OSV:" instead of
    # "from JIRA:" — _extract_jira_hints must accept both so verify-cves-in-source
    # can process CVEs enriched via the OSV fallback path.
    notes = [
        "Package name from OSV: 'ansible-core' (PyPI; upstream name, may differ from RPM name)"
    ]
    pkg, ver = _extract_jira_hints(notes)
    assert pkg == "ansible-core"
    assert ver is None


# ── _read_pip_lockfile ────────────────────────────────────────────────────────

def test_read_pip_lockfile_basic(tmp_path):
    lock_dir = tmp_path / "lockfiles"
    lock_dir.mkdir()
    (lock_dir / "requirements.txt").write_text(
        "# autogenerated\n"
        "axios==1.15.0 ; sys_platform == 'linux'\n"
        "    # via some-parent\n"
        "requests==2.31.0\n"
        "Django==4.2.0\n"
        "\n"
    )
    index, lockfile = _read_pip_lockfile(str(tmp_path))
    assert lockfile is not None
    assert index.get("requests") == "2.31.0"
    assert index.get("django") == "4.2.0"
    assert index.get("axios") == "1.15.0"


def test_read_pip_lockfile_normalizes_names(tmp_path):
    lock_dir = tmp_path / "lockfiles"
    lock_dir.mkdir()
    (lock_dir / "requirements.txt").write_text("My_Package==1.0.0\n")
    index, _ = _read_pip_lockfile(str(tmp_path))
    assert index.get("my-package") == "1.0.0"


def test_read_pip_lockfile_strips_extras(tmp_path):
    lock_dir = tmp_path / "lockfiles"
    lock_dir.mkdir()
    (lock_dir / "requirements.txt").write_text("requests[security]==2.31.0\n")
    index, _ = _read_pip_lockfile(str(tmp_path))
    assert index.get("requests") == "2.31.0"


def test_read_pip_lockfile_missing(tmp_path):
    index, lockfile = _read_pip_lockfile(str(tmp_path))
    assert index == {}
    assert lockfile is None


def test_read_pip_lockfile_merges_requirements_build(tmp_path):
    lock_dir = tmp_path / "lockfiles"
    lock_dir.mkdir()
    (lock_dir / "requirements.txt").write_text("requests==2.31.0\n")
    (lock_dir / "requirements-build.txt").write_text("pip==26.1.2\nsetuptools==70.0.0\n")
    index, lockfile = _read_pip_lockfile(str(tmp_path))
    assert index.get("requests") == "2.31.0"
    assert index.get("pip") == "26.1.2"
    assert index.get("setuptools") == "70.0.0"
    assert "requirements.txt" in lockfile
    assert "requirements-build.txt" in lockfile


def test_read_pip_lockfile_no_uv_lock(tmp_path):
    # uv.lock should be ignored even when present
    lock_dir = tmp_path / "lockfiles"
    lock_dir.mkdir()
    (lock_dir / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "uv.lock").write_text("version = 1\n")
    index, lockfile = _read_pip_lockfile(str(tmp_path))
    assert "requests" in index
    assert "uv.lock" not in (lockfile or "")


# ── _read_npm_lockfile ────────────────────────────────────────────────────────

def _make_npm_lock(tmp_path, packages: dict, version: int = 3) -> pathlib.Path:
    data = {
        "name": "test",
        "lockfileVersion": version,
        "packages": {
            "": {"name": "test"},
            **packages,
        },
    }
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps(data))
    return tmp_path


def test_read_npm_lockfile_basic(tmp_path):
    _make_npm_lock(tmp_path, {
        "node_modules/axios": {"version": "1.15.0"},
        "node_modules/react": {"version": "18.0.0"},
    })
    index, lockfile = _read_npm_lockfile(str(tmp_path))
    assert lockfile is not None
    assert index.get("axios") == "1.15.0"
    assert index.get("react") == "18.0.0"


def test_read_npm_lockfile_case_insensitive(tmp_path):
    _make_npm_lock(tmp_path, {"node_modules/Axios": {"version": "1.15.0"}})
    index, _ = _read_npm_lockfile(str(tmp_path))
    assert index.get("axios") == "1.15.0"


def test_read_npm_lockfile_scoped(tmp_path):
    _make_npm_lock(tmp_path, {
        "node_modules/@patternfly/react-core": {"version": "6.4.1"},
    })
    index, _ = _read_npm_lockfile(str(tmp_path))
    assert index.get("@patternfly/react-core") == "6.4.1"


def test_read_npm_lockfile_prefers_direct_over_nested(tmp_path):
    _make_npm_lock(tmp_path, {
        "node_modules/axios": {"version": "1.16.0"},
        "node_modules/some-parent/node_modules/axios": {"version": "1.14.0"},
    })
    index, _ = _read_npm_lockfile(str(tmp_path))
    assert index.get("axios") == "1.16.0"


def test_read_npm_lockfile_missing(tmp_path):
    index, lockfile = _read_npm_lockfile(str(tmp_path))
    assert index == {}
    assert lockfile is None


# ── check_cve_in_source ───────────────────────────────────────────────────────

def _cve_with_notes(pkg="Axios", ver="1.16.0"):
    return {
        "cve_id": "CVE-2026-44486",
        "notes": [
            f"Package name from JIRA: '{pkg}' (upstream name; may differ from RPM name)",
            f"Upstream fixed version from JIRA: {ver} (semver, not an RPM NVR)",
        ],
        "affected_containers": [],
    }


def test_check_source_fixed():
    index = {"axios": "1.16.0"}
    result = check_cve_in_source(_cve_with_notes(), "ui", index, "package-lock.json", "npm")
    assert result["package_found"] is True
    assert result["is_fixed"] is True
    assert result["installed_version"] == "1.16.0"
    assert result["minimum_fixed_version"] == "1.16.0"


def test_check_source_not_fixed():
    index = {"axios": "1.15.0"}
    result = check_cve_in_source(_cve_with_notes(), "ui", index, "package-lock.json", "npm")
    assert result["package_found"] is True
    assert result["is_fixed"] is False


def test_check_source_package_not_found():
    index = {"react": "18.0.0"}
    result = check_cve_in_source(_cve_with_notes(), "ui", index, "package-lock.json", "npm")
    assert result["package_found"] is False
    assert result["is_fixed"] is None


def test_check_source_case_insensitive_npm():
    # JIRA note says "Axios" (capital A); npm index has "axios" (lowercase)
    index = {"axios": "1.17.0"}
    result = check_cve_in_source(_cve_with_notes(pkg="Axios"), "ui", index, "package-lock.json", "npm")
    assert result["package_found"] is True
    assert result["is_fixed"] is True


def test_check_source_no_pkg_name_in_notes():
    # No package name at all → nothing to look up
    cve = {"cve_id": "CVE-2026-99999", "notes": [], "affected_containers": []}
    result = check_cve_in_source(cve, "ui", {"axios": "1.16.0"}, "package-lock.json", "npm")
    assert result["package_found"] is False
    assert result["is_fixed"] is None


def test_check_source_package_found_no_fixed_version(monkeypatch):
    # Package name known, package IS in lockfile, but no advisory exists yet.
    # Should report package_found=True and installed_version, is_fixed stays None.
    fake_cve_id = "CVE-9999-99999"
    monkeypatch.setitem(_advisory_cache, fake_cve_id, [])  # empty — no advisory
    # No GHSA ID means the code falls through to NVD on the second advisory lookup
    # (with the real installed version).  Block that subprocess/HTTP call too.
    monkeypatch.setattr(_mod, "_nvd_fixed_version", lambda *a, **kw: None)
    cve = {
        "cve_id": fake_cve_id,
        "notes": [f"Package name from JIRA: 'ws' (upstream name; may differ from RPM name)"],
        "affected_containers": [],
    }
    index = {"ws": "8.21.0"}
    result = check_cve_in_source(cve, "ui", index, "package-lock.json", "npm")
    assert result["package_found"] is True
    assert result["installed_version"] == "8.21.0"
    assert result["minimum_fixed_version"] is None
    assert result["is_fixed"] is None


def test_check_source_package_not_present_no_fixed_version(monkeypatch):
    # Package name known, but NOT in lockfile, and no fixed version.
    # package_found stays False, is_fixed stays None.
    # Populate cache to prevent subprocess call to `gh api` (not caught by socket guard).
    monkeypatch.setitem(_advisory_cache, "CVE-2026-00001", [])
    cve = {
        "cve_id": "CVE-2026-00001",
        "notes": ["Package name from JIRA: 'missing-pkg' (upstream name; may differ from RPM name)"],
        "affected_containers": [],
    }
    result = check_cve_in_source(cve, "ui", {"other": "1.0.0"}, "package-lock.json", "npm")
    assert result["package_found"] is False
    assert result["installed_version"] is None
    assert result["is_fixed"] is None


def test_check_source_empty_index():
    result = check_cve_in_source(_cve_with_notes(), "ui", {}, None, "npm")
    assert result["package_found"] is False
    assert result["is_fixed"] is None


def test_check_source_trailing_period_in_fixed_version():
    index = {"axios": "0.32.0"}
    result = check_cve_in_source(_cve_with_notes(ver="0.32.0."), "ui", index, "package-lock.json", "npm")
    assert result["is_fixed"] is True


# ── merge_source_into_upstream (loaded from compare-cve-results.py) ───────────

def _load_compare():
    path = (pathlib.Path(__file__).parent.parent
            / ".claude/skills/verify-cves-in-builds/scripts/compare-cve-results.py")
    spec = importlib.util.spec_from_file_location("compare_cve_results", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_cmp = _load_compare()
merge_source_into_upstream = _cmp.merge_source_into_upstream
container_delta = _cmp.container_delta
source_aware_delta = _cmp.source_aware_delta


def _src_entry(is_fixed, pkg="axios", lockfile="package-lock.json"):
    return {
        "check_type": "source",
        "lockfile": lockfile,
        "package_found": is_fixed is not None,
        "package_name": pkg,
        "installed_version": "1.16.0" if is_fixed else "1.15.0",
        "minimum_fixed_version": "1.16.0",
        "is_fixed": is_fixed,
    }


def _rpm_entry(is_fixed):
    return {
        "is_fixed": is_fixed,
        "searched_names": ["somepkg"],
        "package_found": is_fixed is not None,
    }


def test_merge_replaces_none_upstream():
    us = {"ui": {"is_fixed": None, "searched_names": [], "package_found": False}}
    src = {"ui": _src_entry(True)}
    merged = merge_source_into_upstream(us, src)
    assert merged["ui"]["is_fixed"] is True
    assert merged["ui"]["source_check"] is True
    assert merged["ui"]["searched_names"] == ["axios"]


def test_merge_does_not_replace_definitive_upstream():
    us = {"ui": {"is_fixed": False, "searched_names": ["somepkg"], "package_found": True}}
    src = {"ui": _src_entry(True)}
    merged = merge_source_into_upstream(us, src)
    # Definitive False upstream should NOT be overridden
    assert merged["ui"]["is_fixed"] is False
    assert "source_check" not in merged["ui"]


def test_merge_skips_when_source_not_found_and_no_fix():
    # package_found=False AND is_fixed=None → nothing useful → skip
    us = {"ui": {"is_fixed": None, "searched_names": [], "package_found": False}}
    src = {"ui": _src_entry(None)}  # _src_entry(None) sets package_found=False
    merged = merge_source_into_upstream(us, src)
    assert merged["ui"]["is_fixed"] is None
    assert "source_check" not in merged["ui"]


def test_merge_includes_when_package_found_but_no_fix():
    # package_found=True but is_fixed=None (no advisory yet) → merge for version context
    us = {"ui": {"is_fixed": None, "searched_names": [], "package_found": False}}
    src = {
        "ui": {
            "check_type": "source",
            "lockfile": "package-lock.json",
            "package_found": True,
            "package_name": "ws",
            "installed_version": "8.21.0",
            "minimum_fixed_version": None,
            "is_fixed": None,
        }
    }
    merged = merge_source_into_upstream(us, src)
    assert merged["ui"]["source_check"] is True
    assert merged["ui"]["installed_version"] == "8.21.0"
    assert merged["ui"]["is_fixed"] is None


def test_merge_adds_missing_container():
    us = {}
    src = {"ui": _src_entry(False)}
    merged = merge_source_into_upstream(us, src)
    assert merged["ui"]["is_fixed"] is False
    assert merged["ui"]["source_check"] is True


def test_merge_source_fixed_then_delta_is_fixed_upstream_not_downstream():
    # ds: unknown (non-RPM package can't be found via RPM); us: fixed in source
    # source_aware_delta should return fixed_upstream_not_downstream
    ds = {"is_fixed": None, "searched_names": [], "package_found": False}
    us_none = {"is_fixed": None, "searched_names": [], "package_found": False}
    us_containers = {"ui": us_none}
    src_containers = {"ui": _src_entry(True)}
    merged = merge_source_into_upstream(us_containers, src_containers)
    delta = source_aware_delta(ds, merged["ui"])
    assert delta == "fixed_upstream_not_downstream"


def test_merge_source_not_fixed_then_delta_is_not_fixed_in_either():
    # ds: unknown; us: not fixed in source → not_fixed_in_either
    ds = {"is_fixed": None, "searched_names": [], "package_found": False}
    us_none = {"is_fixed": None, "searched_names": [], "package_found": False}
    us_containers = {"ui": us_none}
    src_containers = {"ui": _src_entry(False)}
    merged = merge_source_into_upstream(us_containers, src_containers)
    delta = source_aware_delta(ds, merged["ui"])
    assert delta == "not_fixed_in_either"


# ── version_in_range ─────────────────────────────────────────────────────────

def test_version_in_range_lte():
    assert version_in_range("3.1.1", "<= 3.1.1") is True
    assert version_in_range("3.1.2", "<= 3.1.1") is False


def test_version_in_range_lt():
    assert version_in_range("8.20.9", "< 8.21.0") is True
    assert version_in_range("8.21.0", "< 8.21.0") is False


def test_version_in_range_gte_and_lt():
    assert version_in_range("8.5.0",  ">= 8.0.0, < 8.21.0") is True
    assert version_in_range("8.21.0", ">= 8.0.0, < 8.21.0") is False
    assert version_in_range("7.9.9",  ">= 8.0.0, < 8.21.0") is False


def test_version_in_range_gte_and_lte():
    assert version_in_range("1.1.0", ">= 1.1.0, <= 1.8.3") is True
    assert version_in_range("1.8.3", ">= 1.1.0, <= 1.8.3") is True
    assert version_in_range("1.8.4", ">= 1.1.0, <= 1.8.3") is False
    assert version_in_range("1.0.9", ">= 1.1.0, <= 1.8.3") is False


def test_version_in_range_eq():
    assert version_in_range("1.0.0", "= 1.0.0") is True
    assert version_in_range("1.0.1", "= 1.0.0") is False


# ── _get_ghsa_fixed_version ───────────────────────────────────────────────────

def _make_advisory(cve_id, ghsa_id, ecosystem, pkg_name, ranges):
    """Build a fake GitHub advisory structure matching the real API shape."""
    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "vulnerabilities": [
            {
                "package": {"ecosystem": ecosystem, "name": pkg_name},
                "vulnerable_version_range": vr,
                "first_patched_version": fp,
            }
            for vr, fp in ranges
        ],
    }


def _with_cache(cve_id, advisories):
    """Context manager: temporarily inject advisories into the module cache."""
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        _advisory_cache[cve_id] = advisories
        try:
            yield
        finally:
            _advisory_cache.pop(cve_id, None)

    return _ctx()


def test_get_ghsa_fixed_version_single_range():
    adv = _make_advisory("CVE-2026-6322", "GHSA-v39h-62p7-jpjc", "npm", "fast-uri",
                         [("<= 3.1.1", "3.1.2")])
    with _with_cache("CVE-2026-6322", [adv]):
        fixed, ghsa, below_range = _get_ghsa_fixed_version("CVE-2026-6322", "npm", "fast-uri", "3.1.1")
    assert fixed == "3.1.2"
    assert ghsa == "GHSA-v39h-62p7-jpjc"
    assert below_range is False


def test_get_ghsa_fixed_version_multi_range_picks_correct_one():
    # ws has 4 ranges; installed is 8.21.0 which is the fix boundary
    ranges = [
        (">= 1.1.0, < 5.2.5", "5.2.5"),
        (">= 6.0.0, < 6.2.4", "6.2.4"),
        (">= 7.0.0, < 7.5.11", "7.5.11"),
        (">= 8.0.0, < 8.21.0", "8.21.0"),
    ]
    adv = _make_advisory("CVE-2026-48779", "GHSA-96hv-2xvq-fx4p", "npm", "ws", ranges)
    # 8.20.0 is in the >= 8.0.0, < 8.21.0 range
    with _with_cache("CVE-2026-48779", [adv]):
        fixed, ghsa, below_range = _get_ghsa_fixed_version("CVE-2026-48779", "npm", "ws", "8.20.0")
    assert fixed == "8.21.0"
    assert ghsa == "GHSA-96hv-2xvq-fx4p"
    assert below_range is False


def test_get_ghsa_installed_at_fix_version():
    # 8.21.0 is the fix itself. Lower bound 8.0.0 is satisfied (8.21.0 >= 8.0.0),
    # so the range is found and first_patched_version is returned.
    # version_gte("8.21.0", "8.21.0") = True → is_fixed=True downstream.
    ranges = [(">= 8.0.0, < 8.21.0", "8.21.0")]
    adv = _make_advisory("CVE-2026-48779", "GHSA-96hv-2xvq-fx4p", "npm", "ws", ranges)
    with _with_cache("CVE-2026-48779", [adv]):
        fixed, ghsa, below_range = _get_ghsa_fixed_version("CVE-2026-48779", "npm", "ws", "8.21.0")
    assert fixed == "8.21.0"
    assert ghsa == "GHSA-96hv-2xvq-fx4p"
    assert below_range is False


def test_get_ghsa_installed_above_all_series():
    # Hypothetical: installed 9.0.0 but only 8.x range exists. Lower bound 8.0.0
    # is satisfied by 9.0.0, so the 8.x range is picked as most specific.
    ranges = [(">= 8.0.0, < 8.21.0", "8.21.0")]
    adv = _make_advisory("CVE-X", "GHSA-X", "npm", "ws", ranges)
    with _with_cache("CVE-X", [adv]):
        fixed, _, below_range = _get_ghsa_fixed_version("CVE-X", "npm", "ws", "9.0.0")
    assert fixed == "8.21.0"  # range found; version_gte("9.0.0","8.21.0")=True → fixed
    assert below_range is False


def test_get_ghsa_wrong_ecosystem_ignored():
    adv = _make_advisory("CVE-X", "GHSA-X", "pip", "fast-uri", [("<= 3.1.1", "3.1.2")])
    with _with_cache("CVE-X", [adv]):
        fixed, _, below_range = _get_ghsa_fixed_version("CVE-X", "npm", "fast-uri", "3.1.1")
    assert fixed is None
    assert below_range is False


def test_get_ghsa_case_insensitive_package_name():
    adv = _make_advisory("CVE-2026-9277", "GHSA-w", "npm", "shell-quote",
                         [(">= 1.1.0, <= 1.8.3", "1.8.4")])
    with _with_cache("CVE-2026-9277", [adv]):
        # JIRA provides "Shell-Quote" with capital letters
        fixed, _, below_range = _get_ghsa_fixed_version("CVE-2026-9277", "npm", "Shell-Quote", "1.8.3")
    assert fixed == "1.8.4"


def test_get_ghsa_below_all_ranges_returns_flag():
    # image-size case: installed 0.5.5, GHSA ranges start at >= 1.1.0 and >= 2.0.0.
    # Version predates all documented vulnerable ranges → below_range=True.
    ranges = [
        (">= 1.1.0, < 1.2.1", "1.2.1"),
        (">= 2.0.0, < 2.0.2", "2.0.2"),
    ]
    adv = _make_advisory("CVE-2025-71319", "GHSA-m5qc-5hw7-8vg7", "npm", "image-size", ranges)
    with _with_cache("CVE-2025-71319", [adv]):
        fixed, ghsa, below_range = _get_ghsa_fixed_version("CVE-2025-71319", "npm", "image-size", "0.5.5")
    assert fixed is None
    assert ghsa == "GHSA-m5qc-5hw7-8vg7"
    assert below_range is True


def test_get_ghsa_below_range_single_range():
    # Installed 0.9.0 with range >= 1.0.0 → predates vulnerability.
    ranges = [(">= 1.0.0, < 1.5.0", "1.5.0")]
    adv = _make_advisory("CVE-X", "GHSA-X", "npm", "somelib", ranges)
    with _with_cache("CVE-X", [adv]):
        fixed, ghsa, below_range = _get_ghsa_fixed_version("CVE-X", "npm", "somelib", "0.9.0")
    assert fixed is None
    assert ghsa == "GHSA-X"
    assert below_range is True


def test_check_source_below_vulnerable_range(monkeypatch):
    # image-size 0.5.5 is below all GHSA documented vulnerable ranges.
    # The pipeline should mark it is_fixed=True (version predates vulnerability).
    adv = _make_advisory("CVE-2025-71319", "GHSA-m5qc-5hw7-8vg7", "npm", "image-size", [
        (">= 1.1.0, < 1.2.1", "1.2.1"),
        (">= 2.0.0, < 2.0.2", "2.0.2"),
    ])
    monkeypatch.setitem(_advisory_cache, "CVE-2025-71319", [adv])

    cve = {
        "cve_id": "CVE-2025-71319",
        "notes": ["Package name from JIRA: 'image-size' (upstream name; may differ from RPM name)"],
        "affected_containers": [],
    }
    result = check_cve_in_source(cve, "discovery/discovery-ui-rhel9",
                                  {"image-size": "0.5.5"}, "package-lock.json", "npm")
    assert result["package_found"] is True
    assert result["installed_version"] == "0.5.5"
    assert result["is_fixed"] is True
    assert result["ghsa_source"] == "GHSA-m5qc-5hw7-8vg7"
    assert "(below" in result["minimum_fixed_version"]


def test_check_source_ghsa_fallback(monkeypatch):
    # CVE has package name in notes but no fixed version — GHSA lookup fills it in
    adv = _make_advisory("CVE-2026-48779", "GHSA-96hv-2xvq-fx4p", "npm", "ws",
                         [(">= 8.0.0, < 8.21.0", "8.21.0")])
    monkeypatch.setitem(_advisory_cache, "CVE-2026-48779", [adv])
    # OSV is fetched for canonical package name when a GHSA ID is present.
    # Provide a minimal truthy stub so the `or` short-circuits and the CVE-ID
    # fallback fetch is never attempted.  No "affected" key → no canonical name
    # extracted, which is fine: fix version already comes from GHSA.
    monkeypatch.setitem(_osv_cache, "GHSA-96hv-2xvq-fx4p", {"id": "GHSA-96hv-2xvq-fx4p"})

    cve = {
        "cve_id": "CVE-2026-48779",
        "notes": ["Package name from JIRA: 'ws' (upstream name; may differ from RPM name)"],
        "affected_containers": [],
    }
    result = check_cve_in_source(cve, "ui", {"ws": "8.20.0"}, "package-lock.json", "npm")
    assert result["package_found"] is True
    assert result["installed_version"] == "8.20.0"
    assert result["minimum_fixed_version"] == "8.21.0"
    assert result["is_fixed"] is False
    assert result["ghsa_source"] == "GHSA-96hv-2xvq-fx4p"


def test_check_source_ghsa_fallback_already_fixed(monkeypatch):
    adv = _make_advisory("CVE-2026-48779", "GHSA-96hv-2xvq-fx4p", "npm", "ws",
                         [(">= 8.0.0, < 8.21.0", "8.21.0")])
    monkeypatch.setitem(_advisory_cache, "CVE-2026-48779", [adv])
    monkeypatch.setitem(_osv_cache, "GHSA-96hv-2xvq-fx4p", {"id": "GHSA-96hv-2xvq-fx4p"})

    cve = {
        "cve_id": "CVE-2026-48779",
        "notes": ["Package name from JIRA: 'ws' (upstream name; may differ from RPM name)"],
        "affected_containers": [],
    }
    # 8.21.0 satisfies the lower bound >= 8.0.0, so the 8.x series range is found.
    # version_gte("8.21.0", "8.21.0") = True → is_fixed = True.
    result = check_cve_in_source(cve, "ui", {"ws": "8.21.0"}, "package-lock.json", "npm")
    assert result["package_found"] is True
    assert result["installed_version"] == "8.21.0"
    assert result["minimum_fixed_version"] == "8.21.0"
    assert result["is_fixed"] is True
    assert result["ghsa_source"] == "GHSA-96hv-2xvq-fx4p"


# ── _lookup_in_index ─────────────────────────────────────────────────────────

def test_lookup_direct_match():
    index = {"pip": "25.0.1"}
    ver, name = _lookup_in_index("pip", "pip", None, index, "pip")
    assert ver == "25.0.1"
    assert name == "pip"


def test_lookup_osv_canonical_fallback():
    # JIRA name "python-pip" doesn't match; OSV canonical "pip" does
    index = {"pip": "25.0.1"}
    ver, name = _lookup_in_index("python-pip", "python-pip", "pip", index, "pip")
    assert ver == "25.0.1"
    assert name == "pip"


def test_lookup_prefix_stripping():
    # "python-pip" → strip "python-" → "pip"
    index = {"pip": "25.0.1"}
    ver, name = _lookup_in_index("python-pip", "python-pip", None, index, "pip")
    assert ver == "25.0.1"


def test_lookup_python3_prefix_stripping():
    # "python3-requests" → "requests"
    index = {"requests": "2.31.0"}
    ver, name = _lookup_in_index("python3-requests", "python3-requests", None, index, "pip")
    assert ver == "2.31.0"


def test_lookup_not_found():
    index = {"something-else": "1.0.0"}
    ver, name = _lookup_in_index("missing-pkg", "missing-pkg", None, index, "pip")
    assert ver is None
    assert name is None


# ── _osv_fixed_version ────────────────────────────────────────────────────────

def _make_osv(pkg_name, ecosystem, events_list):
    """Build a minimal OSV advisory structure."""
    return {
        "affected": [
            {
                "package": {"name": pkg_name, "ecosystem": ecosystem},
                "ranges": [{"type": "ECOSYSTEM", "events": events}
                           for events in events_list],
            }
        ]
    }


def test_osv_fixed_version_basic():
    osv = _make_osv("pip", "PyPI", [[{"introduced": "0"}, {"fixed": "26.1.2"}]])
    assert _osv_fixed_version(osv, "pypi", "pip", "25.0.1") == "26.1.2"


def test_osv_fixed_version_already_fixed():
    # 26.1.2 is at or above the fix — introduced=0, so range applies; returns "26.1.2"
    osv = _make_osv("pip", "PyPI", [[{"introduced": "0"}, {"fixed": "26.1.2"}]])
    assert _osv_fixed_version(osv, "pypi", "pip", "26.1.2") == "26.1.2"


def test_osv_fixed_version_multi_range():
    # Same as ws — multiple introduced/fixed pairs
    osv = _make_osv("ws", "npm", [
        [{"introduced": "1.1.0"}, {"fixed": "5.2.5"}],
        [{"introduced": "6.0.0"}, {"fixed": "6.2.4"}],
        [{"introduced": "8.0.0"}, {"fixed": "8.21.0"}],
    ])
    # 8.x installed → picks the range with highest matching lower bound (8.0.0)
    assert _osv_fixed_version(osv, "npm", "ws", "8.20.0") == "8.21.0"


def test_osv_fixed_version_wrong_ecosystem():
    osv = _make_osv("pip", "PyPI", [[{"introduced": "0"}, {"fixed": "26.1.2"}]])
    assert _osv_fixed_version(osv, "npm", "pip", "25.0.1") is None


def test_check_source_osv_fallback_pip(monkeypatch):
    # Simulate: CVE with "python-pip" in JIRA notes, no fixed version,
    # GHSA has empty vulnerabilities, OSV has canonical name "pip" + fix "26.1.2"
    fake_cve_id = "CVE-9999-PIP"
    # GHSA returns advisory with no vulnerabilities
    monkeypatch.setitem(_advisory_cache, fake_cve_id, [{"ghsa_id": "GHSA-fake", "vulnerabilities": []}])
    # OSV returns canonical name + version range
    osv_data = _make_osv("pip", "PyPI", [[{"introduced": "0"}, {"fixed": "26.1.2"}]])
    monkeypatch.setitem(_osv_cache, "GHSA-fake", osv_data)

    cve = {
        "cve_id": fake_cve_id,
        "notes": ["Package name from JIRA: 'python-pip' (upstream name; may differ from RPM name)"],
        "affected_containers": [],
    }
    # requirements-build.txt has pip==25.0.1
    index = {"pip": "25.0.1"}
    result = check_cve_in_source(cve, "server", index, "lockfiles/requirements-build.txt", "pip")
    assert result["package_found"] is True
    assert result["installed_version"] == "25.0.1"
    assert result["minimum_fixed_version"] == "26.1.2"
    assert result["is_fixed"] is False


def test_check_source_jira_fix_version_wrong_major_stream(monkeypatch):
    # CVE-2026-14257 (brace-expansion): JIRA only recorded the highest-stream fix (5.0.8),
    # but quipucords-ui has 1.1.18 which satisfies the 1.x stream fix of 1.1.17.
    # The check must fall back to advisory lookup with the actual installed version
    # and find the stream-specific fix, then report is_fixed=True.
    adv = _make_advisory(
        "CVE-2026-14257", "GHSA-fake-brace-exp", "npm", "brace-expansion",
        [
            (">= 0, < 1.1.17", "1.1.17"),
            (">= 2.0.0, < 2.1.3", "2.1.3"),
            (">= 3.0.0, < 3.0.3", "3.0.3"),
            (">= 5.0.0, < 5.0.8", "5.0.8"),
        ],
    )
    monkeypatch.setitem(_advisory_cache, "CVE-2026-14257", [adv])
    monkeypatch.setitem(_osv_cache, "GHSA-fake-brace-exp", {"id": "GHSA-fake-brace-exp"})

    cve = {
        "cve_id": "CVE-2026-14257",
        "notes": [
            "Package name from JIRA: 'brace-expansion' (upstream name; may differ from RPM name)",
            "Upstream fixed version from JIRA: 5.0.8 (semver, not an RPM NVR)",
        ],
        "affected_containers": [],
    }
    result = check_cve_in_source(cve, "ui", {"brace-expansion": "1.1.18"},
                                  "package-lock.json", "npm")
    assert result["package_found"] is True
    assert result["installed_version"] == "1.1.18"
    assert result["minimum_fixed_version"] == "1.1.17"
    assert result["is_fixed"] is True


def test_source_aware_delta_does_not_affect_non_source_entries():
    # container_delta and source_aware_delta should agree on RPM-only entries
    ds = {"is_fixed": None, "searched_names": [], "package_found": False}
    us = {"is_fixed": True, "searched_names": ["pkg"], "package_found": True}
    assert container_delta(ds, us) == "unknown"
    assert source_aware_delta(ds, us) == "unknown"  # no source_check flag → unchanged
