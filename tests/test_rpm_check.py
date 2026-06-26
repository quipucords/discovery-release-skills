"""Tests for parsing and version comparison logic in check-cves-in-rpms.py."""
import importlib.util
import pathlib
import sys
import unittest.mock


def _load():
    path = (pathlib.Path(__file__).parent.parent
            / ".claude/skills/verify-cves-in-builds/scripts/check-cves-in-rpms.py")
    spec = importlib.util.spec_from_file_location("check_cves_in_rpms", path)
    mod = importlib.util.module_from_spec(spec)
    # The module runs file I/O at import time. To get all function definitions to
    # execute (including those after the loading block), we make open() return valid
    # empty JSON so load_json() returns {} and the for loop over containers runs
    # cleanly (no container matches empty checked_images). Execution then continues
    # until unified['cves'] crashes — by which point all functions are defined.
    with (unittest.mock.patch("sys.argv", ["check-cves-in-rpms.py", "--set", "downstream"]),
          unittest.mock.patch("builtins.open", unittest.mock.mock_open(read_data="{}")),
          unittest.mock.patch("sys.exit")):
        try:
            spec.loader.exec_module(mod)
        except Exception:
            pass
    return mod


_mod = _load()
parse_nvra = _mod.parse_nvra
parse_evr = _mod.parse_evr
rpmvercmp = _mod.rpmvercmp
evr_gte = _mod.evr_gte
package_name_from_entry = _mod.package_name_from_entry
_is_module_stream_nvr = _mod._is_module_stream_nvr
load_rpm_list = _mod.load_rpm_list
check_cve_in_container = _mod.check_cve_in_container


# ── parse_nvra ────────────────────────────────────────────────────────────────

def test_parse_nvra_simple():
    r = parse_nvra("openssl-3.0.7-28.el9_3.x86_64")
    assert r == {"name": "openssl", "version": "3.0.7", "release": "28.el9_3", "arch": "x86_64"}

def test_parse_nvra_noarch():
    r = parse_nvra("python3-pip-23.3.1-1.el9.noarch")
    assert r == {"name": "python3-pip", "version": "23.3.1", "release": "1.el9", "arch": "noarch"}

def test_parse_nvra_hyphenated_name():
    r = parse_nvra("python3-six-1.16.0-9.el9.noarch")
    assert r["name"] == "python3-six"
    assert r["version"] == "1.16.0"
    assert r["release"] == "9.el9"

def test_parse_nvra_epoch_like_version():
    r = parse_nvra("openssh-9.9p1-7.el9_8.x86_64")
    assert r["name"] == "openssh"
    assert r["version"] == "9.9p1"
    assert r["release"] == "7.el9_8"

def test_parse_nvra_no_arch_dot_returns_none():
    assert parse_nvra("gpg-pubkey-abcdef12") is None

def test_parse_nvra_empty_string_returns_none():
    assert parse_nvra("") is None

def test_parse_nvra_no_hyphens_returns_none():
    assert parse_nvra("nodots") is None

def test_parse_nvra_module_stream_nvra():
    r = parse_nvra("nginx-1.24.0-5.module+el9.4.0+21920+7a3e4dba.x86_64")
    assert r["name"] == "nginx"
    assert r["version"] == "1.24.0"


# ── parse_evr ─────────────────────────────────────────────────────────────────

def test_parse_evr_with_epoch():
    assert parse_evr("1:2.0.0-5.el9") == ("1", "2.0.0", "5.el9")

def test_parse_evr_no_epoch():
    assert parse_evr("2.0.0-5.el9") == ("0", "2.0.0", "5.el9")

def test_parse_evr_version_only_no_release():
    epoch, ver, rel = parse_evr("3.9.18")
    assert epoch == "0"
    assert ver == "3.9.18"
    assert rel == "0"

def test_parse_evr_strips_package_name_prefix():
    epoch, ver, rel = parse_evr("openssh-9.9p1-7.el9_8")
    assert epoch == "0"
    assert ver == "9.9p1"
    assert rel == "7.el9_8"

def test_parse_evr_vr_pair():
    assert parse_evr("9.9p1-7.el9_8") == ("0", "9.9p1", "7.el9_8")

def test_parse_evr_numeric_prefix_not_stripped():
    # String that starts with a digit is not treated as package name.
    assert parse_evr("3.0.7-28.el9_3") == ("0", "3.0.7", "28.el9_3")


# ── rpmvercmp ─────────────────────────────────────────────────────────────────

def test_rpmvercmp_equal_strings():
    assert rpmvercmp("1.0.0", "1.0.0") == 0

def test_rpmvercmp_numeric_greater_than():
    assert rpmvercmp("10", "9") > 0

def test_rpmvercmp_numeric_less_than():
    assert rpmvercmp("9", "10") < 0

def test_rpmvercmp_numeric_beats_alpha():
    assert rpmvercmp("1", "a") > 0
    assert rpmvercmp("a", "1") < 0

def test_rpmvercmp_alpha_ordering():
    assert rpmvercmp("b", "a") > 0
    assert rpmvercmp("a", "b") < 0

def test_rpmvercmp_multi_segment_greater():
    assert rpmvercmp("1.2.3", "1.2.2") > 0

def test_rpmvercmp_multi_segment_less():
    assert rpmvercmp("1.2.2", "1.2.3") < 0

def test_rpmvercmp_multi_segment_equal():
    assert rpmvercmp("1.2.3", "1.2.3") == 0

def test_rpmvercmp_tilde_sorts_before_everything():
    assert rpmvercmp("~alpha", "1.0") < 0
    assert rpmvercmp("1.0", "~alpha") > 0

def test_rpmvercmp_prerelease_before_release():
    assert rpmvercmp("1.0~rc1", "1.0") < 0

def test_rpmvercmp_longer_wins():
    assert rpmvercmp("1.0.0", "1.0") > 0

def test_rpmvercmp_el9_subrelease_ordering():
    assert rpmvercmp("7.el9_2", "7.el9_1") > 0
    assert rpmvercmp("7.el9_1", "7.el9_2") < 0

def test_rpmvercmp_leading_zeros_ignored_in_numerics():
    # "09" and "9" are both parsed as integer 9 — equal.
    assert rpmvercmp("09", "9") == 0


# ── evr_gte ───────────────────────────────────────────────────────────────────

def test_evr_gte_installed_above_fixed():
    assert evr_gte("9.9p1-8.el9_8", "openssh-9.9p1-7.el9_8") is True

def test_evr_gte_installed_exactly_at_fixed():
    assert evr_gte("9.9p1-7.el9_8", "openssh-9.9p1-7.el9_8") is True

def test_evr_gte_installed_below_fixed():
    assert evr_gte("9.8p1-5.el9", "openssh-9.9p1-7.el9_8") is False

def test_evr_gte_epoch_wins_over_version():
    # Higher epoch always trumps version number.
    assert evr_gte("1:1.0.0-1.el9", "0:9.9.9-99.el9") is True
    assert evr_gte("0:9.9.9-99.el9", "1:1.0.0-1.el9") is False

def test_evr_gte_numeric_version_semantics():
    # "1.10" > "1.9" because 10 > 9 numerically.
    assert evr_gte("1.10.0-1.el9", "1.9.0-1.el9") is True
    assert evr_gte("1.9.0-1.el9", "1.10.0-1.el9") is False

def test_evr_gte_same_version_higher_release():
    assert evr_gte("3.0.7-29.el9_3", "openssl-3.0.7-28.el9_3") is True

def test_evr_gte_same_version_lower_release():
    assert evr_gte("3.0.7-27.el9_3", "openssl-3.0.7-28.el9_3") is False


# ── _is_module_stream_nvr ─────────────────────────────────────────────────────

def test_is_module_stream_nvr_timestamp_release_detected():
    assert _is_module_stream_nvr("nginx-1.24-9080020260610161820.9") is True

def test_is_module_stream_nvr_regular_el9():
    assert _is_module_stream_nvr("nginx-1.24.0-5.el9") is False

def test_is_module_stream_nvr_openssh_regular():
    assert _is_module_stream_nvr("openssh-9.9p1-7.el9_8") is False

def test_is_module_stream_nvr_python_regular():
    assert _is_module_stream_nvr("python3-3.9.18-3.el9") is False

def test_is_module_stream_nvr_binary_rpm_from_module():
    # Binary RPMs built from a module stream have normal el9 releases.
    assert _is_module_stream_nvr("nginx-1.24.0-5.module+el9.4.0+21920+7a3e4dba") is False


# ── package_name_from_entry ───────────────────────────────────────────────────

def test_package_name_from_name_field():
    assert package_name_from_entry({"name": "openssh"}) == "openssh"

def test_package_name_from_nvr():
    assert package_name_from_entry({"nvr": "openssh-9.9p1-7.el9_8"}) == "openssh"

def test_package_name_from_rpm_nvras():
    assert package_name_from_entry({"rpm_nvras": ["glib2-2.68.4-14.el9.x86_64"]}) == "glib2"

def test_package_name_empty_entry_returns_none():
    assert package_name_from_entry({}) is None

def test_package_name_name_takes_precedence_over_nvr():
    result = package_name_from_entry({"name": "openssh", "nvr": "other-1.0-1.el9"})
    assert result == "openssh"


# ── load_rpm_list ─────────────────────────────────────────────────────────────

def test_load_rpm_list_parses_valid_lines():
    content = "openssl-3.0.7-28.el9_3.x86_64\npython3-pip-23.3.1-1.el9.noarch\n"
    m = unittest.mock.mock_open(read_data=content)
    with unittest.mock.patch("builtins.open", m):
        index, skipped = load_rpm_list("fake.txt")
    assert "openssl" in index
    assert "python3-pip" in index
    assert skipped == []

def test_load_rpm_list_skips_unparseable_lines():
    content = "gpg-pubkey-abcdef12\nopenssl-3.0.7-28.el9_3.x86_64\n"
    m = unittest.mock.mock_open(read_data=content)
    with unittest.mock.patch("builtins.open", m):
        index, skipped = load_rpm_list("fake.txt")
    assert "openssl" in index
    assert len(skipped) == 1

def test_load_rpm_list_empty_file():
    m = unittest.mock.mock_open(read_data="")
    with unittest.mock.patch("builtins.open", m):
        index, skipped = load_rpm_list("fake.txt")
    assert index == {}
    assert skipped == []

def test_load_rpm_list_file_not_found():
    with unittest.mock.patch("builtins.open", side_effect=FileNotFoundError):
        index, skipped = load_rpm_list("nonexistent.txt")
    assert index == {}

def test_load_rpm_list_indexes_by_name():
    content = "openssl-3.0.7-28.el9_3.x86_64\nopenssl-3.0.7-28.el9_3.i686\n"
    m = unittest.mock.mock_open(read_data=content)
    with unittest.mock.patch("builtins.open", m):
        index, _ = load_rpm_list("fake.txt")
    # Both x86_64 and i686 variants indexed under the same name.
    assert len(index["openssl"]) == 2


# ── check_cve_in_container ────────────────────────────────────────────────────

CONTAINER = "discovery/discovery-server-rhel9"


def _setup(container, nvra_list, image="sha256:abc"):
    """Patch module-level globals for check_cve_in_container tests."""
    _mod.checked_images = {container: {"image": image}}
    _mod.rpm_index = {container: {}}
    for nvra_str in nvra_list:
        parsed = parse_nvra(nvra_str)
        if parsed:
            _mod.rpm_index[container].setdefault(parsed["name"], []).append(
                {**parsed, "nvra": nvra_str}
            )


def _cve(cve_id, vulnerable=None, fixed=None):
    return {
        "cve_id": cve_id,
        "vulnerable_packages": vulnerable or [],
        "fixed_packages": fixed or [],
    }


def test_check_cve_package_fixed():
    _setup(CONTAINER, ["openssh-9.9p1-8.el9_8.x86_64"])
    result = check_cve_in_container(
        _cve("CVE-2026-T1",
             vulnerable=[{"name": "openssh"}],
             fixed=[{"name": "openssh", "nvr": "openssh-9.9p1-7.el9_8"}]),
        CONTAINER,
    )
    assert result["package_found"] is True
    assert result["is_fixed"] is True


def test_check_cve_package_not_fixed():
    _setup(CONTAINER, ["openssh-9.8p1-5.el9.x86_64"])
    result = check_cve_in_container(
        _cve("CVE-2026-T2",
             vulnerable=[{"name": "openssh"}],
             fixed=[{"name": "openssh", "nvr": "openssh-9.9p1-7.el9_8"}]),
        CONTAINER,
    )
    assert result["package_found"] is True
    assert result["is_fixed"] is False


def test_check_cve_package_not_in_container():
    _setup(CONTAINER, ["glib2-2.68.4-14.el9.x86_64"])
    result = check_cve_in_container(
        _cve("CVE-2026-T3",
             vulnerable=[{"name": "openssh"}],
             fixed=[{"name": "openssh", "nvr": "openssh-9.9p1-7.el9_8"}]),
        CONTAINER,
    )
    assert result["package_found"] is False
    assert result["is_fixed"] is None


def test_check_cve_no_package_data_returns_early():
    _setup(CONTAINER, [])
    result = check_cve_in_container(_cve("CVE-2026-T4"), CONTAINER)
    assert result["package_found"] is False
    assert result["searched_names"] == []
    assert result["is_fixed"] is None


def test_check_cve_module_stream_fixed_nvr_skipped():
    # Module stream NVRs in fixed_packages must be ignored; is_fixed stays None.
    _setup(CONTAINER, ["nginx-1.24.0-5.module+el9.4.0+21920+7a3e4dba.x86_64"])
    with unittest.mock.patch.object(_mod, "_advisory_fix_version", return_value=None):
        result = check_cve_in_container(
            _cve("CVE-2026-T5",
                 vulnerable=[{"name": "nginx"}],
                 fixed=[{"name": "nginx", "nvr": "nginx-1.24-9080020260610161820.9"}]),
            CONTAINER,
        )
    assert result["package_found"] is True
    assert result["is_fixed"] is None


def test_check_cve_searched_names_recorded():
    _setup(CONTAINER, ["openssl-3.0.7-28.el9_3.x86_64"])
    result = check_cve_in_container(
        _cve("CVE-2026-T6",
             vulnerable=[{"name": "openssl"}],
             fixed=[{"name": "openssl", "nvr": "openssl-3.0.7-29.el9_3"}]),
        CONTAINER,
    )
    assert "openssl" in result["searched_names"]


def test_check_cve_minimum_fixed_nvr_set():
    _setup(CONTAINER, ["openssl-3.0.7-28.el9_3.x86_64"])
    result = check_cve_in_container(
        _cve("CVE-2026-T7",
             vulnerable=[{"name": "openssl"}],
             fixed=[{"name": "openssl", "nvr": "openssl-3.0.7-29.el9_3"}]),
        CONTAINER,
    )
    assert result["minimum_fixed_nvr"] == "openssl-3.0.7-29.el9_3"


def test_check_cve_multiple_fixed_nvrs_picks_minimum():
    # When two NVRs for the same package exist (different RHEL releases), the
    # lower one must be used to avoid a false "fixed" verdict.
    _setup(CONTAINER, ["openssl-3.0.7-28.el9_3.x86_64"])
    result = check_cve_in_container(
        _cve("CVE-2026-T8",
             vulnerable=[{"name": "openssl"}],
             fixed=[
                 {"name": "openssl", "nvr": "openssl-3.0.7-30.el9_4"},
                 {"name": "openssl", "nvr": "openssl-3.0.7-29.el9_3"},
             ]),
        CONTAINER,
    )
    # Installed (28) is below both fixed (29, 30) — not fixed.
    assert result["is_fixed"] is False


def test_check_cve_all_packages_must_be_fixed():
    # If a CVE matches two packages and one is not fixed, overall is_fixed = False.
    _setup(CONTAINER, [
        "openssl-3.0.7-29.el9_3.x86_64",  # at fixed version
        "openssl-libs-3.0.7-27.el9_3.x86_64",  # below fixed version
    ])
    result = check_cve_in_container(
        _cve("CVE-2026-T9",
             vulnerable=[{"name": "openssl"}, {"name": "openssl-libs"}],
             fixed=[
                 {"name": "openssl", "nvr": "openssl-3.0.7-29.el9_3"},
                 {"name": "openssl-libs", "nvr": "openssl-libs-3.0.7-29.el9_3"},
             ]),
        CONTAINER,
    )
    assert result["package_found"] is True
    assert result["is_fixed"] is False


def test_check_cve_checked_image_url_in_result():
    _setup(CONTAINER, [])
    result = check_cve_in_container(_cve("CVE-2026-T10"), CONTAINER)
    assert result["checked_image"] == "sha256:abc"
