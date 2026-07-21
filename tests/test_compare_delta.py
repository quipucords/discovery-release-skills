import importlib.util
import pathlib


def _load():
    path = (pathlib.Path(__file__).parent.parent
            / ".claude/skills/verify-cves-in-builds/scripts/compare-cve-results.py")
    spec = importlib.util.spec_from_file_location("compare_cve_results", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_mod = _load()
container_delta = _mod.container_delta
source_aware_delta = _mod.source_aware_delta
cve_delta = _mod.cve_delta
DELTA_PRIORITY = _mod.DELTA_PRIORITY


def _entry(is_fixed, searched=("pkg",)):
    return {"is_fixed": is_fixed, "searched_names": list(searched), "package_found": is_fixed is not None}


def test_fixed_in_both():
    assert container_delta(_entry(True), _entry(True)) == "fixed_in_both"


def test_fixed_upstream_not_downstream():
    assert container_delta(_entry(False), _entry(True)) == "fixed_upstream_not_downstream"


def test_not_fixed_in_either():
    assert container_delta(_entry(False), _entry(False)) == "not_fixed_in_either"


def test_fixed_downstream_not_upstream():
    assert container_delta(_entry(True), _entry(False)) == "fixed_downstream_not_upstream"


def test_unknown_when_is_fixed_none():
    assert container_delta(_entry(None), _entry(True)) == "unknown"


def test_unknown_when_no_searched_names():
    assert container_delta(_entry(False, []), _entry(False, [])) == "unknown"


def test_unknown_when_one_side_has_no_searched_names():
    # ds searched nothing (is_fixed=None), us found and fixed the package
    # is_fixed=None on ds side causes fallthrough → "unknown"
    ds = {"is_fixed": None, "searched_names": [], "package_found": False}
    us = {"is_fixed": True,  "searched_names": ["pkg"], "package_found": True}
    assert container_delta(ds, us) == "unknown"


def test_unknown_when_entry_none():
    assert container_delta(None, _entry(True)) == "unknown"


def test_cve_delta_most_urgent_wins():
    deltas = {"server": "fixed_in_both", "ui": "fixed_upstream_not_downstream"}
    assert cve_delta(deltas) == "fixed_upstream_not_downstream"


def test_cve_delta_empty_is_unknown():
    assert cve_delta({}) == "unknown"


def test_cve_delta_all_fixed():
    assert cve_delta({"s": "fixed_in_both", "u": "fixed_in_both"}) == "fixed_in_both"


def test_delta_priority_first_is_most_urgent():
    assert DELTA_PRIORITY[0] == "fixed_downstream_not_upstream"
    assert DELTA_PRIORITY[-1] == "fixed_in_both"


def test_regression_beats_pending_release():
    # A container with a regression should outrank one just pending a release
    deltas = {"server": "fixed_upstream_not_downstream", "ui": "fixed_downstream_not_upstream"}
    assert cve_delta(deltas) == "fixed_downstream_not_upstream"


# ── fix_available parameter on container_delta ────────────────────────────────
# CVE-2026-11332: JIRA-only CVE, fix_available=False, no package data on either side.
# Without a package name to search for, the delta was "unknown" — but we know the
# fix hasn't been released yet, so it should be "not_fixed_in_either".

def test_no_package_data_fix_unavailable_is_not_fixed_in_either():
    ds = {"is_fixed": None, "searched_names": [], "package_found": False}
    us = {"is_fixed": None, "searched_names": [], "package_found": False}
    assert container_delta(ds, us, fix_available=False) == "not_fixed_in_either"


def test_no_package_data_fix_available_none_stays_unknown():
    # Default: fix_available omitted (None) → unknown, as before.
    ds = {"is_fixed": None, "searched_names": [], "package_found": False}
    us = {"is_fixed": None, "searched_names": [], "package_found": False}
    assert container_delta(ds, us) == "unknown"
    assert container_delta(ds, us, fix_available=None) == "unknown"


def test_no_package_data_fix_available_true_stays_unknown():
    # fix_available=True means a fix exists in errata but we couldn't match a package —
    # still unknown because we can't confirm the container got it.
    ds = {"is_fixed": None, "searched_names": [], "package_found": False}
    us = {"is_fixed": None, "searched_names": [], "package_found": False}
    assert container_delta(ds, us, fix_available=True) == "unknown"


# ── source_aware_delta propagates fix_available ───────────────────────────────

def test_source_aware_delta_fix_unavailable_is_not_fixed_in_either():
    # fix_available=False must propagate through source_aware_delta so the
    # no-package-data case is classified correctly, not left as "unknown".
    ds = {"is_fixed": None, "searched_names": [], "package_found": False}
    us = {"is_fixed": None, "searched_names": [], "package_found": False}
    assert source_aware_delta(ds, us, fix_available=False) == "not_fixed_in_either"


def test_source_aware_delta_fix_available_none_stays_unknown():
    ds = {"is_fixed": None, "searched_names": [], "package_found": False}
    us = {"is_fixed": None, "searched_names": [], "package_found": False}
    assert source_aware_delta(ds, us) == "unknown"
