"""Tests for merge-cve-data.py pure functions."""
import importlib.util
import pathlib


def _load():
    path = (pathlib.Path(__file__).parent.parent
            / ".claude/skills/merge-cve-data/scripts/merge-cve-data.py")
    spec = importlib.util.spec_from_file_location("merge_cve_data", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_mod = _load()
best_severity = _mod.best_severity
normalize_container = _mod.normalize_container
add_container = _mod.add_container
get_or_create_cve = _mod.get_or_create_cve
build_errata_index = _mod.build_errata_index
_is_module_stream_nvr = _mod._is_module_stream_nvr
_rpm_filename_to_nvr = _mod._rpm_filename_to_nvr
extract_fixed_packages = _mod.extract_fixed_packages
process_catalog = _mod.process_catalog
process_prograde = _mod.process_prograde
process_jira = _mod.process_jira
build_summary = _mod.build_summary


# ── best_severity ─────────────────────────────────────────────────────────────

def test_best_severity_both_none():
    assert best_severity(None, None) is None

def test_best_severity_current_none():
    assert best_severity(None, "Important") == "Important"

def test_best_severity_candidate_none():
    assert best_severity("Important", None) == "Important"

def test_best_severity_higher_candidate_wins():
    assert best_severity("Moderate", "Critical") == "Critical"

def test_best_severity_equal():
    assert best_severity("Important", "Important") == "Important"

def test_best_severity_keeps_current_when_higher():
    assert best_severity("Critical", "Low") == "Critical"

def test_best_severity_unknown_loses_to_low():
    assert best_severity("Unknown", "Low") == "Low"

def test_best_severity_all_levels_ordered():
    levels = ["Critical", "Important", "Moderate", "Low", "Unknown"]
    for i, high in enumerate(levels):
        for low in levels[i + 1:]:
            assert best_severity(low, high) == high


# ── normalize_container ───────────────────────────────────────────────────────

def test_normalize_container_none():
    assert normalize_container(None) is None

def test_normalize_container_server_alias():
    assert normalize_container("redhat-user-workloads/discovery-server") == "discovery/discovery-server-rhel9"

def test_normalize_container_ui_alias():
    assert normalize_container("redhat-user-workloads/discovery-ui") == "discovery/discovery-ui-rhel9"

def test_normalize_container_canonical_passthrough():
    assert normalize_container("discovery/discovery-server-rhel9") == "discovery/discovery-server-rhel9"

def test_normalize_container_unknown_passthrough():
    assert normalize_container("other-team/some-container") == "other-team/some-container"


# ── add_container ─────────────────────────────────────────────────────────────

def _record():
    return {"affected_containers": []}

def test_add_container_basic():
    rec = _record()
    add_container(rec, "discovery/discovery-server-rhel9", [])
    assert rec["affected_containers"] == ["discovery/discovery-server-rhel9"]

def test_add_container_no_duplicate():
    rec = _record()
    add_container(rec, "discovery/discovery-server-rhel9", [])
    add_container(rec, "discovery/discovery-server-rhel9", [])
    assert len(rec["affected_containers"]) == 1

def test_add_container_prefix_filter_allows():
    rec = _record()
    add_container(rec, "discovery/discovery-server-rhel9", ["discovery/"])
    assert "discovery/discovery-server-rhel9" in rec["affected_containers"]

def test_add_container_prefix_filter_blocks():
    rec = _record()
    add_container(rec, "other-team/some-container", ["discovery/"])
    assert rec["affected_containers"] == []

def test_add_container_no_prefix_filter_allows_anything():
    rec = _record()
    add_container(rec, "other-team/some-container", [])
    assert "other-team/some-container" in rec["affected_containers"]

def test_add_container_alias_normalized_before_filter():
    rec = _record()
    add_container(rec, "redhat-user-workloads/discovery-server", ["discovery/"])
    assert rec["affected_containers"] == ["discovery/discovery-server-rhel9"]

def test_add_container_none_skipped():
    rec = _record()
    add_container(rec, None, [])
    assert rec["affected_containers"] == []

def test_add_container_multiple_prefixes():
    rec = _record()
    add_container(rec, "teamb/container", ["discovery/", "teamb/"])
    assert "teamb/container" in rec["affected_containers"]


# ── build_errata_index ────────────────────────────────────────────────────────

def _errata(input_id, numeric_id=None, cves=None):
    e = {"input_advisory_id": str(input_id), "cve_ids": cves or []}
    if numeric_id is not None:
        e["advisory_id"] = numeric_id
    return e

def test_build_errata_index_by_string_input_id():
    idx = build_errata_index([_errata("RHSA-2026:1234")])
    assert "RHSA-2026:1234" in idx

def test_build_errata_index_by_numeric_input_id():
    idx = build_errata_index([_errata("165721")])
    assert "165721" in idx

def test_build_errata_index_numeric_advisory_id_also_indexed():
    # When input is RHSA string but API returns numeric_id, both get indexed.
    e = {"input_advisory_id": "RHSA-2026:1234", "advisory_id": 165721, "cve_ids": []}
    idx = build_errata_index([e])
    assert "RHSA-2026:1234" in idx
    assert "165721" in idx

def test_build_errata_index_same_id_not_double_indexed():
    # When numeric_id matches the string input_id, it is not added twice.
    e = {"input_advisory_id": "165721", "advisory_id": 165721, "cve_ids": []}
    idx = build_errata_index([e])
    # Both point to the same entry; no KeyError expected.
    assert idx["165721"] is e

def test_build_errata_index_skips_error_entries():
    entries = [
        {"error": "auth failed", "input_advisory_id": "165721"},
        _errata("RHSA-2026:9999"),
    ]
    idx = build_errata_index(entries)
    assert "RHSA-2026:9999" in idx
    assert "165721" not in idx

def test_build_errata_index_empty():
    assert build_errata_index([]) == {}

def test_build_errata_index_multiple_entries():
    idx = build_errata_index([_errata("RHSA-2026:0001"), _errata("RHSA-2026:0002")])
    assert "RHSA-2026:0001" in idx
    assert "RHSA-2026:0002" in idx


# ── _is_module_stream_nvr ─────────────────────────────────────────────────────

def test_is_module_stream_nvr_detects_timestamp_release():
    assert _is_module_stream_nvr("nginx-1.24-9080020260610161820.9") is True

def test_is_module_stream_nvr_regular_el9():
    assert _is_module_stream_nvr("nginx-1.24.0-5.el9") is False

def test_is_module_stream_nvr_openssh():
    assert _is_module_stream_nvr("openssh-9.9p1-7.el9_8") is False

def test_is_module_stream_nvr_python():
    assert _is_module_stream_nvr("python3-3.9.18-3.el9") is False

def test_is_module_stream_nvr_ten_digit_release():
    # Release that is exactly 10 digits triggers detection.
    assert _is_module_stream_nvr("perl-5.32-1234567890.el9") is True


# ── _rpm_filename_to_nvr ──────────────────────────────────────────────────────

def test_rpm_filename_to_nvr_x86_64():
    assert _rpm_filename_to_nvr("openssh-9.9p1-7.el9_8.x86_64.rpm") == "openssh-9.9p1-7.el9_8"

def test_rpm_filename_to_nvr_noarch():
    assert _rpm_filename_to_nvr("python3-pip-23.3.1-1.el9.noarch.rpm") == "python3-pip-23.3.1-1.el9"

def test_rpm_filename_to_nvr_aarch64():
    assert _rpm_filename_to_nvr("glib2-2.68.4-14.el9.aarch64.rpm") == "glib2-2.68.4-14.el9"

def test_rpm_filename_to_nvr_src_stripped():
    assert _rpm_filename_to_nvr("openssh-9.9p1-7.el9_8.src.rpm") == "openssh-9.9p1-7.el9_8"

def test_rpm_filename_to_nvr_unknown_arch_passthrough():
    # Unrecognised arch suffix is kept; the whole name-minus-.rpm is returned.
    result = _rpm_filename_to_nvr("somepkg-1.0-1.weirdarch.rpm")
    assert result == "somepkg-1.0-1.weirdarch"


# ── extract_fixed_packages ────────────────────────────────────────────────────

def _regular_build(nvr, name, version, release, epoch=None):
    return {"nvr": nvr, "name": name, "epoch": epoch, "version": version, "release": release}

def _regular_errata(release_key, build):
    return {
        "releases": {
            release_key: {
                "release_name": release_key,
                "builds": [build],
            }
        }
    }

def test_extract_fixed_packages_regular_build():
    entry = _regular_errata(
        "RHEL-9.4.0.GA",
        _regular_build("openssh-9.9p1-7.el9_8", "openssh", "9.9p1", "7.el9_8"),
    )
    pkgs = extract_fixed_packages(entry)
    assert len(pkgs) == 1
    assert pkgs[0]["nvr"] == "openssh-9.9p1-7.el9_8"
    assert pkgs[0]["name"] == "openssh"
    assert pkgs[0]["release_name"] == "RHEL-9.4.0.GA"

def test_extract_fixed_packages_preserves_epoch():
    entry = _regular_errata(
        "RHEL-9.4.0.GA",
        _regular_build("python3-3.9.18-3.el9", "python3", "3.9.18", "3.el9", epoch="0"),
    )
    pkgs = extract_fixed_packages(entry)
    assert pkgs[0]["epoch"] == "0"

def test_extract_fixed_packages_module_stream_uses_binary_rpms():
    entry = {
        "releases": {
            "RHEL-9.4.0.GA": {
                "release_name": "RHEL-9.4.0.GA",
                "builds": [{
                    "nvr": "nginx-1.24-9080020260610161820.9",
                    "name": "nginx",
                    "epoch": None,
                    "version": "1.24",
                    "release": "9080020260610161820.9",
                    "rpms_by_arch": {
                        "x86_64": [
                            "nginx-1.24.0-5.module+el9.4.0+21920+7a3e4dba.x86_64.rpm",
                            "nginx-mod-http-image-filter-1.24.0-5.module+el9.4.0+21920+7a3e4dba.x86_64.rpm",
                        ],
                        "src": [
                            "nginx-1.24.0-5.module+el9.4.0+21920+7a3e4dba.src.rpm",
                        ],
                    },
                }],
            }
        }
    }
    pkgs = extract_fixed_packages(entry)
    nvrs = {p["nvr"] for p in pkgs}
    # Source RPM must be excluded.
    assert not any("src.rpm" in nvr for nvr in nvrs)
    # Binary RPMs must be present with arch suffix stripped.
    assert "nginx-1.24.0-5.module+el9.4.0+21920+7a3e4dba" in nvrs
    assert "nginx-mod-http-image-filter-1.24.0-5.module+el9.4.0+21920+7a3e4dba" in nvrs

def test_extract_fixed_packages_module_stream_deduplicates_across_arches():
    entry = {
        "releases": {
            "RHEL-9.4.0.GA": {
                "release_name": "RHEL-9.4.0.GA",
                "builds": [{
                    "nvr": "perl-5.32-1234567890.el9",
                    "name": "perl",
                    "epoch": None,
                    "version": "5.32",
                    "release": "1234567890.el9",
                    "rpms_by_arch": {
                        "x86_64": ["perl-5.32.1-480.el9.x86_64.rpm"],
                        "i686":   ["perl-5.32.1-480.el9.x86_64.rpm"],  # same filename in two arch keys
                    },
                }],
            }
        }
    }
    pkgs = extract_fixed_packages(entry)
    nvrs = [p["nvr"] for p in pkgs]
    assert nvrs.count("perl-5.32.1-480.el9") == 1

def test_extract_fixed_packages_empty_releases():
    assert extract_fixed_packages({"releases": {}}) == []

def test_extract_fixed_packages_multiple_releases():
    entry = {
        "releases": {
            "RHEL-9.4.0.GA": {
                "release_name": "RHEL-9.4.0.GA",
                "builds": [_regular_build("pkg-1.0-1.el9", "pkg", "1.0", "1.el9")],
            },
            "RHEL-8.10.0.GA": {
                "release_name": "RHEL-8.10.0.GA",
                "builds": [_regular_build("pkg-1.0-1.el8", "pkg", "1.0", "1.el8")],
            },
        }
    }
    pkgs = extract_fixed_packages(entry)
    release_names = {p["release_name"] for p in pkgs}
    assert "RHEL-9.4.0.GA" in release_names
    assert "RHEL-8.10.0.GA" in release_names


# ── process_catalog ───────────────────────────────────────────────────────────

def _catalog_item(cve_id, advisory_id=None, severity="Important",
                  image_name="discovery/discovery-server-rhel9"):
    return {
        "cve_id": cve_id,
        "severity": severity,
        "advisory_id": advisory_id,
        "advisory_link": f"https://access.redhat.com/errata/{advisory_id}" if advisory_id else None,
        "image_name": image_name,
        "affected_packages": [
            {"name": "openssh", "version": "9.8p1", "arch": "x86_64", "package_type": "rpm"}
        ],
        "rpm_nvras": [],
    }

def test_process_catalog_registers_cve():
    registry = {}
    process_catalog({"cves": [_catalog_item("CVE-2026-1234", "RHSA-2026:1111")]},
                    registry, {}, [])
    assert "CVE-2026-1234" in registry

def test_process_catalog_sets_severity():
    registry = {}
    process_catalog({"cves": [_catalog_item("CVE-2026-1234", severity="Critical")]},
                    registry, {}, [])
    assert registry["CVE-2026-1234"]["severity"] == "Critical"

def test_process_catalog_sets_advisory_id():
    registry = {}
    process_catalog({"cves": [_catalog_item("CVE-2026-1234", "RHSA-2026:1111")]},
                    registry, {}, [])
    assert registry["CVE-2026-1234"]["advisory_id"] == "RHSA-2026:1111"

def test_process_catalog_marks_catalog_source():
    registry = {}
    process_catalog({"cves": [_catalog_item("CVE-2026-1234")]}, registry, {}, [])
    assert "catalog" in registry["CVE-2026-1234"]["sources"]

def test_process_catalog_enriches_fixed_packages_from_errata():
    errata_index = {
        "RHSA-2026:1111": {
            "releases": {
                "RHEL-9.4.0.GA": {
                    "release_name": "RHEL-9.4.0.GA",
                    "builds": [_regular_build("openssh-9.9p1-7.el9_8", "openssh", "9.9p1", "7.el9_8")],
                }
            }
        }
    }
    registry = {}
    process_catalog({"cves": [_catalog_item("CVE-2026-1234", "RHSA-2026:1111")]},
                    registry, errata_index, [])
    rec = registry["CVE-2026-1234"]
    assert rec["fix_available"] is True
    assert len(rec["fixed_packages"]) == 1
    assert "errata" in rec["sources"]

def test_process_catalog_no_errata_adds_note():
    registry = {}
    process_catalog({"cves": [_catalog_item("CVE-2026-1234", "RHSA-2026:ORPHAN")]},
                    registry, {}, [])
    notes = registry["CVE-2026-1234"]["notes"]
    assert any("no errata data" in n for n in notes)

def test_process_catalog_severity_not_downgraded():
    # First occurrence sets Critical; second occurrence with Moderate should not win.
    registry = {}
    process_catalog({"cves": [
        _catalog_item("CVE-2026-1234", severity="Critical"),
        _catalog_item("CVE-2026-1234", severity="Moderate"),
    ]}, registry, {}, [])
    assert registry["CVE-2026-1234"]["severity"] == "Critical"

def test_process_catalog_container_prefix_filter():
    registry = {}
    process_catalog({"cves": [_catalog_item("CVE-2026-1234", image_name="other-team/container")]},
                    registry, {}, ["discovery/"])
    # CVE is registered but non-discovery container is filtered out.
    assert "CVE-2026-1234" in registry
    assert registry["CVE-2026-1234"]["affected_containers"] == []

def test_process_catalog_no_duplicate_vulnerable_packages():
    registry = {}
    item = _catalog_item("CVE-2026-1234")
    process_catalog({"cves": [item, item]}, registry, {}, [])
    assert len(registry["CVE-2026-1234"]["vulnerable_packages"]) == 1

def test_process_catalog_none_input():
    registry = {}
    process_catalog(None, registry, {}, [])
    assert registry == {}


# ── process_prograde ──────────────────────────────────────────────────────────

def _prograde(advisory_id, containers=None, severity="Important"):
    return {
        "advisory_id": advisory_id,
        "affected_containers": containers or ["discovery/discovery-server-rhel9"],
        "advisory_security_impact": severity,
    }

def _errata_entry(advisory_id, cve_ids, builds=None):
    return {
        "input_advisory_id": str(advisory_id),
        "advisory_id": advisory_id,
        "advisory_name": f"RHSA-2026:{advisory_id}",
        "cve_ids": cve_ids,
        "security_impact": "Important",
        "releases": {} if not builds else {
            "RHEL-9.4.0.GA": {
                "release_name": "RHEL-9.4.0.GA",
                "builds": builds,
            }
        },
    }

def test_process_prograde_links_cves_via_errata():
    registry = {}
    errata_index = {"165721": _errata_entry("165721", ["CVE-2026-5678"])}
    process_prograde({"advisories": [_prograde("165721")]}, registry, errata_index, [])
    assert "CVE-2026-5678" in registry

def test_process_prograde_marks_sources():
    registry = {}
    errata_index = {"165721": _errata_entry("165721", ["CVE-2026-5678"])}
    process_prograde({"advisories": [_prograde("165721")]}, registry, errata_index, [])
    sources = registry["CVE-2026-5678"]["sources"]
    assert "prograde" in sources
    assert "errata" in sources

def test_process_prograde_no_errata_skips():
    registry = {}
    process_prograde({"advisories": [_prograde("999999")]}, registry, {}, [])
    assert len(registry) == 0

def test_process_prograde_container_prefix_filter():
    registry = {}
    errata_index = {"165721": _errata_entry("165721", ["CVE-2026-5678"])}
    process_prograde(
        {"advisories": [_prograde("165721", containers=["other-team/c", "discovery/discovery-server-rhel9"])]},
        registry, errata_index, ["discovery/"],
    )
    containers = registry["CVE-2026-5678"]["affected_containers"]
    assert "discovery/discovery-server-rhel9" in containers
    assert "other-team/c" not in containers

def test_process_prograde_sets_fix_available():
    builds = [_regular_build("openssh-9.9p1-7.el9_8", "openssh", "9.9p1", "7.el9_8")]
    errata_index = {"165721": _errata_entry("165721", ["CVE-2026-5678"], builds=builds)}
    registry = {}
    process_prograde({"advisories": [_prograde("165721")]}, registry, errata_index, [])
    assert registry["CVE-2026-5678"]["fix_available"] is True

def test_process_prograde_no_cve_ids_skips():
    registry = {}
    errata_index = {"165721": _errata_entry("165721", [])}  # empty cve_ids
    process_prograde({"advisories": [_prograde("165721")]}, registry, errata_index, [])
    assert len(registry) == 0

def test_process_prograde_none_input():
    registry = {}
    process_prograde(None, registry, {}, [])
    assert registry == {}


# ── process_jira ──────────────────────────────────────────────────────────────

def _jira_issue(cve_ids, key="DISCOVERY-1234",
                component="redhat-user-workloads/discovery-server"):
    return {
        "key": key,
        "cve_ids": cve_ids,
        "status": "In Progress",
        "duedate": "2026-07-01",
        "url": f"https://issues.redhat.com/browse/{key}",
        "summary": f"CVE issue {key}",
        "downstream_component": component,
        "package_name": "openssh",
        "vulnerable_package_nvrs": [],
        "upstream_fixed_versions": [],
    }

def test_process_jira_registers_cves():
    registry = {}
    process_jira({"issues": [_jira_issue(["CVE-2026-0001"])]}, registry, [])
    assert "CVE-2026-0001" in registry
    assert "jira" in registry["CVE-2026-0001"]["sources"]

def test_process_jira_multiple_cves_per_issue():
    registry = {}
    process_jira({"issues": [_jira_issue(["CVE-2026-0001", "CVE-2026-0002"])]}, registry, [])
    assert "CVE-2026-0001" in registry
    assert "CVE-2026-0002" in registry

def test_process_jira_jira_record_attached():
    registry = {}
    process_jira({"issues": [_jira_issue(["CVE-2026-0001"])]}, registry, [])
    ji = registry["CVE-2026-0001"]["jira_issues"]
    assert len(ji) == 1
    assert ji[0]["key"] == "DISCOVERY-1234"

def test_process_jira_no_duplicate_jira_issues():
    registry = {}
    issue = _jira_issue(["CVE-2026-0001"])
    process_jira({"issues": [issue]}, registry, [])
    process_jira({"issues": [issue]}, registry, [])
    assert len(registry["CVE-2026-0001"]["jira_issues"]) == 1

def test_process_jira_container_alias_normalized():
    registry = {}
    process_jira({"issues": [_jira_issue(["CVE-2026-0001"],
                                          component="redhat-user-workloads/discovery-server")]},
                 registry, [])
    assert "discovery/discovery-server-rhel9" in registry["CVE-2026-0001"]["affected_containers"]

def test_process_jira_empty_cve_ids_skipped():
    registry = {}
    process_jira({"issues": [_jira_issue([])]}, registry, [])
    assert len(registry) == 0

def test_process_jira_vulnerable_nvrs_added():
    registry = {}
    issue = _jira_issue(["CVE-2026-0001"])
    issue["vulnerable_package_nvrs"] = ["openssh-9.8p1-5.el9.x86_64"]
    process_jira({"issues": [issue]}, registry, [])
    vp = registry["CVE-2026-0001"]["vulnerable_packages"]
    assert any(v.get("nvr") == "openssh-9.8p1-5.el9.x86_64" for v in vp)

def test_process_jira_upstream_fixed_versions_noted():
    registry = {}
    issue = _jira_issue(["CVE-2026-0001"])
    issue["upstream_fixed_versions"] = ["9.9p1"]
    process_jira({"issues": [issue]}, registry, [])
    notes = registry["CVE-2026-0001"]["notes"]
    assert any("9.9p1" in n for n in notes)

def test_process_jira_none_input():
    registry = {}
    process_jira(None, registry, [])
    assert registry == {}


# ── build_summary ─────────────────────────────────────────────────────────────

def _cve_rec(severity, fix_available, containers, sources):
    return {
        "severity": severity,
        "fix_available": fix_available,
        "affected_containers": containers,
        "sources": sources,
    }

def test_build_summary_counts_total():
    registry = {
        "CVE-2026-0001": _cve_rec("Critical", True, ["discovery/discovery-server-rhel9"], ["catalog"]),
        "CVE-2026-0002": _cve_rec("Important", False, ["discovery/discovery-server-rhel9"], ["jira"]),
    }
    s = build_summary(registry)
    assert s["total_cves"] == 2
    assert s["fix_available"] == 1
    assert s["fix_unknown"] == 1

def test_build_summary_by_severity():
    registry = {
        "CVE-2026-0001": _cve_rec("Critical", True, [], ["catalog"]),
        "CVE-2026-0002": _cve_rec("Critical", False, [], ["jira"]),
        "CVE-2026-0003": _cve_rec("Moderate", False, [], ["jira"]),
    }
    s = build_summary(registry)
    assert s["by_severity"]["Critical"] == 2
    assert s["by_severity"]["Moderate"] == 1

def test_build_summary_by_container():
    registry = {
        "CVE-2026-0001": _cve_rec("Important", True,
                                   ["discovery/discovery-server-rhel9"], ["catalog"]),
        "CVE-2026-0002": _cve_rec("Important", False,
                                   ["discovery/discovery-server-rhel9",
                                    "discovery/discovery-ui-rhel9"], ["catalog"]),
    }
    s = build_summary(registry)
    assert s["by_container"]["discovery/discovery-server-rhel9"] == 2
    assert s["by_container"]["discovery/discovery-ui-rhel9"] == 1

def test_build_summary_sources_union():
    registry = {
        "CVE-2026-0001": _cve_rec("Important", True, [], ["catalog", "errata"]),
        "CVE-2026-0002": _cve_rec("Important", False, [], ["jira"]),
    }
    s = build_summary(registry)
    assert set(s["sources_used"]) == {"catalog", "errata", "jira"}

def test_build_summary_empty():
    s = build_summary({})
    assert s["total_cves"] == 0
    assert s["fix_available"] == 0
    assert s["fix_unknown"] == 0

def test_build_summary_severity_sorted_high_to_low():
    registry = {
        "CVE-2026-0001": _cve_rec("Low", False, [], ["jira"]),
        "CVE-2026-0002": _cve_rec("Critical", True, [], ["catalog"]),
    }
    s = build_summary(registry)
    keys = list(s["by_severity"].keys())
    assert keys.index("Critical") < keys.index("Low")
