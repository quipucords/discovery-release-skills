"""Tests for _expand_python_names in check-cves-in-rpms.py."""
import importlib.util
import pathlib


def _load():
    path = (pathlib.Path(__file__).parent.parent
            / ".claude/skills/verify-cves-in-builds/scripts/check-cves-in-rpms.py")
    spec = importlib.util.spec_from_file_location("check_cves_in_rpms", path)
    mod = importlib.util.module_from_spec(spec)
    # The module runs at import time, but only reads files that exist.
    # We patch sys.argv and provide empty stubs to avoid side effects.
    import sys, unittest.mock
    with (unittest.mock.patch("sys.argv", ["check-cves-in-rpms.py", "--set", "downstream"]),
          unittest.mock.patch("builtins.open", side_effect=FileNotFoundError),
          unittest.mock.patch("sys.exit")):
        try:
            spec.loader.exec_module(mod)
        except Exception:
            pass
    return mod


_mod = _load()
_expand_python_names = _mod._expand_python_names
_PYTHON_SRPM_RE = _mod._PYTHON_SRPM_RE


def _fake_index(*names):
    """Build a minimal RPM index dict with the given package names."""
    return {name: [{"name": name, "version": "1.0", "release": "1.el9", "arch": "noarch",
                    "nvra": f"{name}-1.0-1.el9.noarch"}]
            for name in names}


def test_non_python_package_unchanged():
    index = _fake_index("nginx", "glib2")
    assert _expand_python_names("nginx", index) == {"nginx"}
    assert _expand_python_names("glib2", index) == {"glib2"}


def test_python_pip_finds_binary_variants():
    index = _fake_index(
        "python3-pip-wheel",
        "python3.12-pip-wheel",
        "python3.12-pip",
        "python3-requests",  # should not be included
    )
    result = _expand_python_names("python-pip", index)
    assert "python-pip" in result          # original always kept
    assert "python3.12-pip" in result
    # Wheel packages are NOT included for a python-pip CVE — they are a
    # separate RPM and only relevant if the CVE targets python-pip-wheel itself.
    assert "python3.12-pip-wheel" not in result
    assert "python3-pip-wheel" not in result
    assert "python3-requests" not in result  # wrong suffix


def test_python_pip_wheel_cve_finds_wheel_packages():
    # When the CVE IS about python-pip-wheel, wheel packages should be found.
    index = _fake_index("python3-pip-wheel", "python3.12-pip-wheel", "python3.12-pip")
    result = _expand_python_names("python-pip-wheel", index)
    assert "python3-pip-wheel" in result
    assert "python3.12-pip-wheel" in result
    assert "python3.12-pip" not in result  # not a wheel package


def test_python_package_not_in_index_keeps_original():
    # If nothing matches in the index, at least keep the original name.
    index = _fake_index("glib2", "openssl")
    result = _expand_python_names("python-requests", index)
    assert result == {"python-requests"}


def test_python_package_adds_versioned_variant():
    index = _fake_index("python3.11-cryptography", "python3.12-cryptography")
    result = _expand_python_names("python-cryptography", index)
    assert "python3.11-cryptography" in result
    assert "python3.12-cryptography" in result


def test_python_prefix_regex_matches_source_names():
    assert _PYTHON_SRPM_RE.match("python-pip")
    assert _PYTHON_SRPM_RE.match("python-cryptography")
    assert not _PYTHON_SRPM_RE.match("python3-pip")   # binary name, not source
    assert not _PYTHON_SRPM_RE.match("glib2")
