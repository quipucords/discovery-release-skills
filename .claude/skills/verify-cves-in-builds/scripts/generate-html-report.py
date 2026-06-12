#!/usr/bin/env python3
"""Generate a self-contained HTML report from cve-data/verified-cves-downstream.json.

All CSS is defined in the <style> block via custom properties — no inline
styles anywhere in the HTML. Dark mode is handled by
@media (prefers-color-scheme: dark) overriding the custom properties.

Reads:  cve-data/verified-cves-downstream.json  (default)
        cve-data/comparison.json                 (with --comparison)
Writes: cve-data/cve-report.html

All progress goes to stderr. Exits non-zero on failure.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from html import escape

parser = argparse.ArgumentParser()
parser.add_argument("--comparison", action="store_true",
                    help="Read comparison.json and render the dual-set comparison report")
parser.add_argument("--set", default="downstream", choices=["downstream", "upstream"],
                    dest="set_name",
                    help="Which image set to report on in single-set mode (default: downstream)")
args = parser.parse_args()

SEVERITY_ORDER = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1, "Unknown": 0}

# Container name constants (must match check-cves-in-rpms.py)
SERVER_CONTAINER = "discovery/discovery-server-rhel9"
UI_CONTAINER     = "discovery/discovery-ui-rhel9"

if args.comparison:
    try:
        with open("cve-data/comparison.json") as f:
            data = json.load(f)
    except FileNotFoundError:
        print("Error: cve-data/comparison.json not found. Run compare-cve-results.py first.",
              file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    mode         = "comparison"
    cves         = data.get("cves", [])
    generated_at = data.get("generated_at", "unknown")
else:
    _sn = args.set_name
    try:
        with open(f"cve-data/verified-cves-{_sn}.json") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: cve-data/verified-cves-{_sn}.json not found.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    mode          = "single"
    verification  = data.get("verification", {})
    images        = verification.get("images", {})
    skipped_nvras = verification.get("skipped_nvras", {})
    vsummary      = data.get("verification_summary", {})
    cves          = data.get("cves", [])
    verified_at   = data.get("verified_at", "unknown")
    generated_at  = verified_at


# ── CSS (pure string — no f-string, so CSS braces need no escaping) ──────────

CSS = """
  /* ── Custom properties (light mode) ─────────────────────────────────── */
  :root {
    --bg:               #f8fafc;
    --surface:          #ffffff;
    --surface-alt:      #f1f5f9;
    --surface-hover:    #f8fafc;
    --border:           #e2e8f0;
    --border-subtle:    #f1f5f9;
    --border-input:     #cbd5e1;

    --text:             #1e293b;
    --text-muted:       #64748b;
    --text-subtle:      #475569;
    --text-link:        #0f172a;

    --header-bg:        #0f172a;
    --header-text:      #f8fafc;
    --header-sub:       #94a3b8;

    --code-bg:          #f1f5f9;
    --footer-text:      #94a3b8;

    --action-bg:        #fef2f2;
    --action-border:    #fca5a5;
    --action-text:      #7f1d1d;
    --action-heading:   #b91c1c;
    --action-link:      #b91c1c;

    /* Severity */
    --sev-critical:     #dc2626;
    --sev-important:    #ea580c;
    --sev-moderate:     #ca8a04;
    --sev-low:          #2563eb;
    --sev-unknown:      #6b7280;

    /* Status */
    --status-fixed:           #16a34a;
    --status-not-fixed:       #dc2626;
    --status-not-found:       #7c3aed;
    --status-no-package-data: #b45309;
    --status-fix-unknown:     #ca8a04;
    --status-na:              #9ca3af;

    /* Delta badges */
    --delta-regression:    #dc2626;
    --delta-not-fixed:     #9a3412;
    --delta-release:       #2563eb;
    --delta-unknown:       #b45309;
    --delta-fixed-both:    #16a34a;

    /* Comparison table column group headers */
    --col-ds: #1d4ed8;
    --col-us: #15803d;

    /* Pending-release (tier 2) banner */
    --release-bg:      #f0fdf4;
    --release-border:  #86efac;
    --release-text:    #14532d;
    --release-heading: #15803d;
    --release-link:    #15803d;
  }

  /* ── Dark mode overrides ─────────────────────────────────────────────── */
  @media (prefers-color-scheme: dark) {
    :root {
      --bg:               #0f172a;
      --surface:          #1e293b;
      --surface-alt:      #1e293b;
      --surface-hover:    #263147;
      --border:           #334155;
      --border-subtle:    #334155;
      --border-input:     #475569;

      --text:             #f1f5f9;
      --text-muted:       #94a3b8;
      --text-subtle:      #94a3b8;
      --text-link:        #93c5fd;

      --header-bg:        #020617;
      --header-text:      #f8fafc;
      --header-sub:       #64748b;

      --code-bg:          #334155;
      --footer-text:      #64748b;

      --action-bg:        #450a0a;
      --action-border:    #7f1d1d;
      --action-text:      #fca5a5;
      --action-heading:   #f87171;
      --action-link:      #f87171;

      /* Severity — slightly lighter for dark backgrounds */
      --sev-critical:     #ef4444;
      --sev-important:    #f97316;
      --sev-moderate:     #eab308;
      --sev-low:          #60a5fa;
      --sev-unknown:      #9ca3af;

      /* Status — slightly lighter for dark backgrounds */
      --status-fixed:           #22c55e;
      --status-not-fixed:       #ef4444;
      --status-not-found:       #a78bfa;
      --status-no-package-data: #f59e0b;
      --status-fix-unknown:     #eab308;
      --status-na:              #6b7280;

      --delta-regression:    #ef4444;
      --delta-not-fixed:     #fb923c;
      --delta-release:       #60a5fa;
      --delta-unknown:       #f59e0b;
      --delta-fixed-both:    #22c55e;

      --col-ds: #60a5fa;
      --col-us: #4ade80;

      --release-bg:      #052e16;
      --release-border:  #15803d;
      --release-text:    #86efac;
      --release-heading: #4ade80;
      --release-link:    #4ade80;
    }
  }

  /* ── Reset & base ────────────────────────────────────────────────────── */
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }

  /* ── Header ──────────────────────────────────────────────────────────── */
  .header { background: var(--header-bg); color: var(--header-text); padding: 1.5rem 2rem; }
  .header h1 { font-size: 1.5rem; font-weight: 700; }
  .header .sub { font-size: 0.85rem; color: var(--header-sub); margin-top: 0.25rem; }

  /* ── Main layout ─────────────────────────────────────────────────────── */
  .main { padding: 2rem; max-width: 1400px; margin: 0 auto; }

  /* ── Summary cards ───────────────────────────────────────────────────── */
  .cards { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
  /* Comparison cards are simpler (no image URL, no 2×2 grid) — allow them to shrink */
  .cards-compare .card { min-width: 0; }
  .cards-compare .card-title { text-align: center; }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 0.75rem;
    padding: 1.25rem;
    min-width: 260px;
    flex: 1;
  }
  .card-title { font-weight: 700; font-size: 1rem; margin-bottom: 0.25rem; }
  .card-image {
    font-size: 0.75rem;
    color: var(--text-muted);
    margin-bottom: 1rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .stat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }
  .stat-grid-single { grid-template-columns: 1fr; }
  .stat {
    text-align: center;
    padding: 0.5rem;
    background: var(--surface-alt);
    border-radius: 0.5rem;
  }
  .stat-n { display: block; font-size: 1.5rem; font-weight: 700; }
  .stat-l {
    display: block;
    font-size: 0.7rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
  }
  /* Stat tile accent colours */
  .stat-not-fixed   .stat-n { color: var(--status-not-fixed); }
  .stat-fixed        .stat-n { color: var(--status-fixed); }
  .stat-not-found   .stat-n { color: var(--status-not-found); }
  .stat-no-pkg-data .stat-n { color: var(--status-no-package-data); }

  /* ── Action-required banner (tier 1 — code changes needed) ──────────── */
  .action-required {
    background: var(--action-bg);
    border: 2px solid var(--action-border);
    border-radius: 0.75rem;
    padding: 1.25rem;
    margin-bottom: 1rem;
  }
  .action-required h2 { color: var(--action-heading); font-size: 1rem; margin-bottom: 0.75rem; }
  .action-required h3 { color: var(--action-heading); font-size: 0.875rem; margin: 0.75rem 0 0.4rem; }
  .action-required p  { font-size: 0.875rem; color: var(--action-text); margin-bottom: 0.5rem; }
  .action-required ul { list-style: disc; padding-left: 1.25rem; font-size: 0.875rem; color: var(--action-text); }
  .action-required li { margin: 0.3rem 0; }
  .action-required a  { color: var(--action-link); }
  .cve-pkg { opacity: 0.65; font-style: italic; }

  /* ── Pending-release banner (tier 2 — just cut a release) ────────────── */
  .action-release {
    background: var(--release-bg);
    border: 2px solid var(--release-border);
    border-radius: 0.75rem;
    padding: 1.25rem;
    margin-bottom: 2rem;
  }
  .action-release h2 { color: var(--release-heading); font-size: 1rem; margin-bottom: 0.75rem; }
  .action-release h3 { color: var(--release-heading); font-size: 0.875rem; margin: 0.75rem 0 0.4rem; }
  .action-release p  { font-size: 0.875rem; color: var(--release-text); margin-bottom: 0.5rem; }
  .action-release ul { list-style: disc; padding-left: 1.25rem; font-size: 0.875rem; color: var(--release-text); }
  .action-release li { margin: 0.3rem 0; }
  .action-release a  { color: var(--release-link); }

  /* ── Filters bar ─────────────────────────────────────────────────────── */
  .filters {
    display: flex;
    gap: 0.75rem;
    flex-wrap: wrap;
    align-items: center;
    margin-bottom: 1rem;
    padding: 1rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 0.75rem;
  }
  .filters label { font-size: 0.8rem; font-weight: 600; color: var(--text-subtle); }
  select, input {
    border: 1px solid var(--border-input);
    border-radius: 0.4rem;
    padding: 0.35rem 0.6rem;
    font-size: 0.85rem;
    background: var(--surface);
    color: var(--text);
  }
  .row-count { font-size: 0.8rem; color: var(--text-muted); margin-left: auto; }
  #f-search  { width: 160px; }

  /* ── CVE table ───────────────────────────────────────────────────────── */
  .table-wrap {
    overflow-x: auto;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 0.75rem;
  }
  table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
  thead th {
    background: var(--surface-alt);
    padding: 0.75rem 1rem;
    text-align: left;
    font-weight: 600;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-subtle);
    position: sticky;
    top: 0;
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
  }
  thead th:hover { background: var(--border); }
  thead th.col-group { text-align: center; cursor: default; letter-spacing: 0.08em; }
  thead th.col-group:hover { background: var(--surface-alt); }
  thead th.col-group-downstream { border-bottom: 3px solid var(--col-ds); color: var(--col-ds); }
  thead th.col-group-upstream   { border-bottom: 3px solid var(--col-us); color: var(--col-us); }
  thead th.sorted-asc::after  { content: " ↑"; }
  thead th.sorted-desc::after { content: " ↓"; }
  tbody tr { border-top: 1px solid var(--border-subtle); transition: background 0.1s; }
  tbody tr:hover { background: var(--surface-hover); }
  tbody tr.hidden { display: none; }
  td { padding: 0.6rem 1rem; vertical-align: middle; }
  td a { color: var(--text-link); text-decoration: none; font-weight: 500; }
  td a:hover { text-decoration: underline; }

  /* ── Badges ──────────────────────────────────────────────────────────── */
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
    color: #fff;
  }
  /* Severity badges */
  .sev-critical     { background: var(--sev-critical); }
  .sev-important    { background: var(--sev-important); }
  .sev-moderate     { background: var(--sev-moderate); }
  .sev-low          { background: var(--sev-low); }
  .sev-unknown      { background: var(--sev-unknown); }
  /* Status badges */
  .status-fixed           { background: var(--status-fixed); }
  .status-not-fixed       { background: var(--status-not-fixed); }
  .status-not-found       { background: var(--status-not-found); }
  .status-no-package-data { background: var(--status-no-package-data); }
  .status-fix-unknown     { background: var(--status-fix-unknown); }
  .status-na              { background: var(--status-na); }
  /* Delta badges */
  .delta-regression   { background: var(--delta-regression); }
  .delta-not-fixed    { background: var(--delta-not-fixed); }
  .delta-release      { background: var(--delta-release); }
  .delta-unknown      { background: var(--delta-unknown); }
  .delta-fixed-both   { background: var(--delta-fixed-both); }

  /* ── Inline code ─────────────────────────────────────────────────────── */
  code {
    background: var(--code-bg);
    padding: 0.1em 0.3em;
    border-radius: 0.2rem;
    font-family: ui-monospace, monospace;
  }

  /* ── Footer ──────────────────────────────────────────────────────────── */
  .footer {
    text-align: center;
    font-size: 0.75rem;
    color: var(--footer-text);
    margin-top: 2rem;
    padding-bottom: 2rem;
  }
"""


# ── HTML helpers ──────────────────────────────────────────────────────────────

def sev_badge(severity, title=""):
    css = f"sev-{severity.lower()}"
    t = f' title="{escape(title)}"' if title else ""
    return f'<span class="badge {css}"{t}>{escape(severity)}</span>'


def status_badge(status_key, label):
    css = f"status-{status_key.replace('_', '-')}"
    return f'<span class="badge {css}">{escape(label)}</span>'


DELTA_META = {
    "fixed_downstream_not_upstream": ("delta-regression","Regression"),
    "not_fixed_in_either":           ("delta-not-fixed", "Not fixed anywhere"),
    "fixed_upstream_not_downstream": ("delta-release",   "Pending release"),
    "unknown":                       ("delta-unknown",   "Unknown"),
    "fixed_in_both":                 ("delta-fixed-both","Fixed everywhere"),
}


def delta_badge(delta_key: str) -> str:
    css, label = DELTA_META.get(delta_key, ("delta-unknown", escape(delta_key)))
    return f'<span class="badge {css}">{label}</span>'


def status_cell(entry: dict | None) -> str:
    """Render a status badge for one container entry in the comparison table."""
    if entry is None:
        return status_badge("na", "N/A")
    is_fixed  = entry.get("is_fixed")
    pkg_found = entry.get("package_found", False)
    searched  = entry.get("searched_names", [])
    if is_fixed is True:
        return status_badge("fixed", "Fixed")
    if is_fixed is False:
        return status_badge("not-fixed", "Not Fixed")
    if pkg_found and is_fixed is None:
        return status_badge("fix-unknown", "Fix Unknown")
    if not pkg_found and searched:
        return status_badge("not-found", "Not Found")
    if not pkg_found and not searched:
        return status_badge("no-package-data", "UNKNOWN")
    return status_badge("na", "N/A")


DELTA_SORT_ORDER = {d: i for i, d in enumerate([
    "fixed_downstream_not_upstream",  # regression — most alarming
    "not_fixed_in_either",            # no fix anywhere
    "fixed_upstream_not_downstream",  # pending downstream release (normal)
    "unknown",
    "fixed_in_both",
])}


def make_comparison_rows(cves: list) -> str:
    """Build one HTML table row per CVE for the unified comparison table."""
    sorted_cves = sorted(cves, key=lambda c: (
        DELTA_SORT_ORDER.get(c.get("delta", "unknown"), 99),
        -SEVERITY_ORDER.get(c.get("severity") or "Unknown", 0),
        c.get("cve_id", ""),
    ))
    parts = []
    for cve in sorted_cves:
        cve_id   = cve.get("cve_id", "")
        cve_link = cve.get("cve_link", f"https://access.redhat.com/security/cve/{cve_id}")
        severity = cve.get("severity") or "Unknown"
        delta    = cve.get("delta", "unknown")
        ds       = cve.get("downstream", {})
        us       = cve.get("upstream", {})
        parts.append(
            f'<tr data-delta="{delta}" data-severity="{severity}">'
            f'<td><a href="{escape(cve_link)}" target="_blank">{escape(cve_id)}</a></td>'
            f'<td>{sev_badge(severity)}</td>'
            f'<td>{status_cell(ds.get(SERVER_CONTAINER))}</td>'
            f'<td>{status_cell(ds.get(UI_CONTAINER))}</td>'
            f'<td>{status_cell(us.get(SERVER_CONTAINER))}</td>'
            f'<td>{status_cell(us.get(UI_CONTAINER))}</td>'
            f'<td>{delta_badge(delta)}</td>'
            f'</tr>'
        )
    return "\n".join(parts)


# ── Build per-CVE rows ────────────────────────────────────────────────────────

def make_rows(cves, images):
    rows = []
    for cve in cves:
        cve_id   = cve.get("cve_id", "")
        cve_link = cve.get("cve_link", f"https://access.redhat.com/security/cve/{cve_id}")
        severity = cve.get("severity") or "Unknown"
        checked  = cve.get("checked_containers", {})
        affected = cve.get("affected_containers", [])

        for container in images:
            if container not in affected:
                continue   # CVE doesn't affect this container — no row needed

            entry         = checked.get(container, {})
            is_fixed      = entry.get("is_fixed")
            pkg_found     = entry.get("package_found", False)
            searched      = entry.get("searched_names", [])
            installed     = entry.get("installed_nvras", [])
            minimum_fixed = entry.get("minimum_fixed_nvr") or ""

            if is_fixed is True:
                status_key, status_label = "fixed", "Fixed"
            elif is_fixed is False:
                status_key, status_label = "not-fixed", "Not Fixed"
            elif pkg_found and is_fixed is None:
                status_key, status_label = "fix-unknown", "Fix Unknown"
            elif not pkg_found and searched:
                status_key, status_label = "not-found", "Not Found"
            elif not pkg_found and not searched:
                status_key, status_label = "no-package-data", "UNKNOWN"
            else:
                status_key, status_label = "na", "N/A"

            rows.append({
                "cve_id":           cve_id,
                "cve_link":         cve_link,
                "severity":         severity,
                "sev_order":        SEVERITY_ORDER.get(severity, 0),
                "container":        container,
                "container_short":  container.split("/")[-1],
                "status_key":       status_key,
                "status_label":     status_label,
                "installed":        ", ".join(installed) if installed else "",
                "minimum_fixed":    minimum_fixed,
                "searched":         ", ".join(searched) if searched else "",
                "checked_image":    entry.get("checked_image", ""),
            })
    return rows


# ── Section builders ──────────────────────────────────────────────────────────

def summary_cards_html():
    parts = []
    for container, image in images.items():
        s     = vsummary.get(container, {})
        short = container.split("/")[-1]
        parts.append(f"""
    <div class="card">
      <div class="card-title">{escape(short)}</div>
      <div class="card-image">{escape(image)}</div>
      <div class="stat-grid">
        <div class="stat stat-not-fixed">
          <span class="stat-n">{s.get('not_fixed', 0)}</span>
          <span class="stat-l">Not Fixed</span>
        </div>
        <div class="stat stat-fixed">
          <span class="stat-n">{s.get('fixed', 0)}</span>
          <span class="stat-l">Fixed</span>
        </div>
        <div class="stat stat-not-found">
          <span class="stat-n">{s.get('not_found', 0)}</span>
          <span class="stat-l">Not Found</span>
        </div>
        <div class="stat stat-no-pkg-data">
          <span class="stat-n">{s.get('no_package_data', 0)}</span>
          <span class="stat-l">UNKNOWN</span>
        </div>
      </div>
    </div>""")
    return "\n".join(parts)


def action_required_html():
    if not any_skipped and not not_found_rows and not no_pkg_data_rows:
        return ""
    parts = ['<div class="action-required"><h2>⚠ ACTION REQUIRED — Manual Verification Needed</h2>']

    if any_skipped:
        parts.append("<h3>RPM entries that could not be parsed</h3>")
        parts.append("<p>These entries were excluded from automated verification. "
                     "Check whether they are relevant to any CVEs in this report.</p><ul>")
        for container, lines in any_skipped.items():
            parts.append(f"<li><strong>{escape(container.split('/')[-1])}</strong>: "
                         + ", ".join(f"<code>{escape(l)}</code>" for l in lines) + "</li>")
        parts.append("</ul>")

    if no_pkg_data_rows:
        parts.append("<h3>CVEs marked UNKNOWN — no RPM package data available</h3>")
        parts.append("<p>These CVEs are reported as affecting the container but no RPM "
                     "package name could be determined. The vulnerable component may be a "
                     "non-RPM dependency (e.g. npm, Python). "
                     "<strong>Investigate each one manually.</strong></p><ul>")
        seen = set()
        for r in sorted(no_pkg_data_rows, key=lambda x: -x["sev_order"]):
            key = (r["cve_id"], r["container_short"])
            if key in seen:
                continue
            seen.add(key)
            parts.append(
                f'<li>{sev_badge(r["severity"])} '
                f'<a href="{escape(r["cve_link"])}" target="_blank">{escape(r["cve_id"])}</a>'
                f' — {escape(r["container_short"])}</li>'
            )
        parts.append("</ul>")

    if not_found_rows:
        parts.append("<h3>CVEs whose packages were not found in the container</h3>")
        parts.append("<p>These CVEs affect the container according to published data, "
                     "but the vulnerable package was not found in the RPM list. "
                     "Verify manually.</p><ul>")
        seen = set()
        for r in sorted(not_found_rows, key=lambda x: -x["sev_order"]):
            key = (r["cve_id"], r["container_short"])
            if key in seen:
                continue
            seen.add(key)
            parts.append(
                f'<li>{sev_badge(r["severity"])} '
                f'<a href="{escape(r["cve_link"])}" target="_blank">{escape(r["cve_id"])}</a>'
                f' — {escape(r["container_short"])} '
                f'(searched for: <code>{escape(r["searched"])}</code>)</li>'
            )
        parts.append("</ul>")

    parts.append("</div>")
    return "\n".join(parts)


def comparison_summary_cards_html(data: dict) -> str:
    """Summary cards for comparison mode — one card per delta category."""
    summary = data.get("summary", {})
    delta_display = [
        ("fixed_downstream_not_upstream", "Regression",        "stat-not-fixed"),
        ("not_fixed_in_either",           "Not fixed anywhere","stat-not-fixed"),
        ("unknown",                       "Unknown",           "stat-no-pkg-data"),
        ("fixed_upstream_not_downstream", "Pending release",   "stat-fixed"),
        ("fixed_in_both",                 "Fixed everywhere",  "stat-fixed"),
    ]
    parts = []
    for key, label, css in delta_display:
        n = summary.get(key, 0)
        parts.append(f"""
    <div class="card">
      <div class="card-title">{label}</div>
      <div class="stat-grid stat-grid-single">
        <div class="stat {css}">
          <span class="stat-n">{n}</span>
          <span class="stat-l">CVEs</span>
        </div>
      </div>
    </div>""")
    return "\n".join(parts)


def comparison_action_required_html(cves: list) -> str:
    """Two-tier action banners for comparison mode.

    Tier 1 (red): issues requiring upstream code changes — regression, not fixed anywhere, unknown.
    Tier 2 (green): fixes that exist upstream but need a downstream release — no code changes needed.
    """
    by_delta: dict[str, list] = {}
    for cve in cves:
        by_delta.setdefault(cve.get("delta", "unknown"), []).append(cve)

    def cve_list_html(group: list) -> str:
        parts = ["<ul>"]
        for cve in group:
            cve_id    = cve.get("cve_id", "")
            cve_link  = cve.get("cve_link", f"https://access.redhat.com/security/cve/{cve_id}")
            sev       = cve.get("severity") or "Unknown"
            pkg_names = cve.get("package_names", [])
            pkg_str   = (f' <span class="cve-pkg">({escape(", ".join(pkg_names))})</span>'
                         if pkg_names else "")
            parts.append(
                f'<li>{sev_badge(sev)} '
                f'<a href="{escape(cve_link)}" target="_blank">{escape(cve_id)}</a>'
                f'{pkg_str}</li>'
            )
        parts.append("</ul>")
        return "\n".join(parts)

    sev_sort = lambda c: -SEVERITY_ORDER.get(c.get("severity") or "Unknown", 0)
    result = ""

    # ── Tier 1: code changes required ────────────────────────────────────────
    tier1_parts = []

    group = sorted(by_delta.get("fixed_downstream_not_upstream", []), key=sev_sort)
    if group:
        tier1_parts.append("<h3>🚨 Upstream regression — fixed downstream but NOT in upstream</h3>")
        tier1_parts.append(
            "<p>The downstream Discovery release contains these fixes, but they have been lost "
            "from the upstream quipucords codebase. This is unexpected! Find and restore the "
            "fix in the upstream quipucords project immediately.</p>"
        )
        tier1_parts.append(cve_list_html(group))

    group = sorted(by_delta.get("not_fixed_in_either", []), key=sev_sort)
    if group:
        tier1_parts.append("<h3>‼️ Not fixed anywhere — develop the fix upstream</h3>")
        tier1_parts.append(
            "<p>No fix exists yet in either the upstream quipucords build or the downstream "
            "Discovery release. Develop and merge the fix into the upstream quipucords project "
            "first; then prepare to include it in a downstream release.</p>"
        )
        tier1_parts.append(cve_list_html(group))

    group = sorted(by_delta.get("unknown", []), key=sev_sort)
    if group:
        tier1_parts.append("<h3>⁉️ UNKNOWN — manual verification needed</h3>")
        tier1_parts.append(
            "<p>No RPM package data is available. The vulnerable component may be a non-RPM "
            "dependency (e.g. npm, Python). <strong>Investigate each CVE manually.</strong></p>"
        )
        tier1_parts.append(cve_list_html(group))

    if tier1_parts:
        result += (
            '<div class="action-required">'
            '<h2>⚠️ Action Required — Upstream code changes needed</h2>'
            + "\n".join(tier1_parts)
            + "</div>\n"
        )

    # ── Tier 2: release action only ──────────────────────────────────────────
    group = sorted(by_delta.get("fixed_upstream_not_downstream", []), key=sev_sort)
    if group:
        result += (
            '<div class="action-release">'
            "<h2>📦 Release Needed — No code changes required</h2>"
            "<h3>Fixed upstream, pending downstream release</h3>"
            "<p>These fixes have been merged to the upstream quipucords codebase. "
            "No further upstream changes are needed. Cut a new downstream Discovery release "
            "to ship them.</p>"
            + cve_list_html(group)
            + "</div>\n"
        )

    return result


def table_rows_html():
    parts = []
    for r in rows:
        parts.append(
            f'<tr data-status="{r["status_key"]}" '
            f'data-container="{r["container_short"]}" '
            f'data-severity="{r["severity"]}">'
            f'<td><a href="{escape(r["cve_link"])}" target="_blank">{escape(r["cve_id"])}</a></td>'
            f'<td>{sev_badge(r["severity"])}</td>'
            f'<td><code>{escape(r["container_short"])}</code></td>'
            f'<td>{status_badge(r["status_key"], r["status_label"])}</td>'
            f'<td><code>{escape(r["installed"])}</code></td>'
            f'<td><code>{escape(r["minimum_fixed"])}</code></td>'
            f'</tr>'
        )
    return "\n".join(parts)


# ── Assemble HTML (mode-specific) ────────────────────────────────────────────

if mode == "comparison":
    title         = "CVE Comparison Report"
    subtitle      = (f"Generated {escape(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))}"
                     f"&nbsp;·&nbsp; Data at: {escape(generated_at[:19].replace('T', ' '))} UTC")
    cards_html    = comparison_summary_cards_html(data)
    cards_class   = "cards-compare"
    action_html   = comparison_action_required_html(cves)
    filters_html  = """
    <label for="f-delta">Delta</label>
    <select id="f-delta" onchange="applyFilters()">
      <option value="">All</option>
      <option value="fixed_downstream_not_upstream">Regression</option>
      <option value="not_fixed_in_either">Not fixed anywhere</option>
      <option value="fixed_upstream_not_downstream">Pending release</option>
      <option value="unknown">Unknown</option>
      <option value="fixed_in_both">Fixed everywhere</option>
    </select>
    <label for="f-severity">Severity</label>
    <select id="f-severity" onchange="applyFilters()">
      <option value="">All</option>
      <option value="Critical">Critical</option>
      <option value="Important">Important</option>
      <option value="Moderate">Moderate</option>
      <option value="Low">Low</option>
      <option value="Unknown">Unknown</option>
    </select>
    <input id="f-search" type="search" placeholder="Search CVE ID…" oninput="applyFilters()">
    <span class="row-count" id="row-count"></span>"""
    thead_html    = """
        <tr>
          <th data-col="0" rowspan="2" onclick="sortTable(0)">CVE ID</th>
          <th data-col="1" rowspan="2" onclick="sortTable(1)">Severity</th>
          <th colspan="2" class="col-group col-group-downstream">Discovery</th>
          <th colspan="2" class="col-group col-group-upstream">quipucords</th>
          <th data-col="6" rowspan="2" onclick="sortTable(6)">Delta</th>
        </tr>
        <tr>
          <th data-col="2" onclick="sortTable(2)">Server</th>
          <th data-col="3" onclick="sortTable(3)">UI</th>
          <th data-col="4" onclick="sortTable(4)">Server</th>
          <th data-col="5" onclick="sortTable(5)">UI</th>
        </tr>"""
    tbody_html    = make_comparison_rows(cves)
    data_ref      = "cve-data/comparison.json"
    js_filter     = """
  const delta    = document.getElementById('f-delta').value;
  const severity = document.getElementById('f-severity').value;
  const search   = document.getElementById('f-search').value.toLowerCase();
  let visible = 0;
  for (const tr of tbody.rows) {
    const show =
      (!delta    || tr.dataset.delta    === delta)    &&
      (!severity || tr.dataset.severity === severity) &&
      (!search   || tr.cells[0].textContent.toLowerCase().includes(search));
    tr.classList.toggle('hidden', !show);
    if (show) visible++;
  }
  countEl.textContent = visible + ' row' + (visible !== 1 ? 's' : '');"""
    js_default_sort = """
  const deltaOrder = {fixed_downstream_not_upstream:0, not_fixed_in_either:1,
                      fixed_upstream_not_downstream:2, unknown:3, fixed_in_both:4};
  const sevOrder   = {Critical:4, Important:3, Moderate:2, Low:1, Unknown:0};
  const rows = Array.from(tbody.rows);
  rows.sort((a, b) => {
    const dd = (deltaOrder[a.dataset.delta] ?? 99) - (deltaOrder[b.dataset.delta] ?? 99);
    if (dd !== 0) return dd;
    return (sevOrder[b.dataset.severity] || 0) - (sevOrder[a.dataset.severity] || 0);
  });
  rows.forEach(r => tbody.appendChild(r));"""

else:  # single-set mode
    rows = make_rows(cves, images)
    any_skipped      = {c: lines for c, lines in skipped_nvras.items() if lines}
    not_found_rows   = [r for r in rows if r["status_key"] == "not-found"]
    no_pkg_data_rows = [r for r in rows if r["status_key"] == "no-package-data"]
    title            = "CVE Build Verification Report"
    subtitle         = (f"Generated {escape(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))}"
                        f"&nbsp;·&nbsp; Data verified at: {escape(verified_at[:19].replace('T', ' '))} UTC")
    cards_html       = summary_cards_html()
    cards_class      = ""
    action_html      = action_required_html()
    container_options = "\n".join(
        f'<option value="{c.split("/")[-1]}">{c.split("/")[-1]}</option>'
        for c in images
    )
    filters_html     = f"""
    <label for="f-container">Container</label>
    <select id="f-container" onchange="applyFilters()">
      <option value="">All</option>
      {container_options}
    </select>
    <label for="f-status">Status</label>
    <select id="f-status" onchange="applyFilters()">
      <option value="">All</option>
      <option value="not-fixed">Not Fixed</option>
      <option value="fixed">Fixed</option>
      <option value="no-package-data">UNKNOWN (no RPM data)</option>
      <option value="not-found">Not Found</option>
      <option value="fix-unknown">Fix Unknown</option>
    </select>
    <label for="f-severity">Severity</label>
    <select id="f-severity" onchange="applyFilters()">
      <option value="">All</option>
      <option value="Critical">Critical</option>
      <option value="Important">Important</option>
      <option value="Moderate">Moderate</option>
      <option value="Low">Low</option>
      <option value="Unknown">Unknown</option>
    </select>
    <input id="f-search" type="search" placeholder="Search CVE ID…"
           oninput="applyFilters()">
    <span class="row-count" id="row-count"></span>"""
    thead_html       = """
        <tr>
          <th data-col="0" onclick="sortTable(0)">CVE ID</th>
          <th data-col="1" onclick="sortTable(1)">Severity</th>
          <th data-col="2" onclick="sortTable(2)">Container</th>
          <th data-col="3" onclick="sortTable(3)">Status</th>
          <th data-col="4" onclick="sortTable(4)">Installed</th>
          <th data-col="5" onclick="sortTable(5)">Minimum Fixed</th>
        </tr>"""
    tbody_html       = table_rows_html()
    data_ref         = f"cve-data/verified-cves-{_sn}.json"
    js_filter        = """
  const container = document.getElementById('f-container').value;
  const status    = document.getElementById('f-status').value;
  const severity  = document.getElementById('f-severity').value;
  const search    = document.getElementById('f-search').value.toLowerCase();
  let visible = 0;
  for (const tr of tbody.rows) {
    const show =
      (!container || tr.dataset.container === container) &&
      (!status    || tr.dataset.status    === status)    &&
      (!severity  || tr.dataset.severity  === severity)  &&
      (!search    || tr.cells[0].textContent.toLowerCase().includes(search));
    tr.classList.toggle('hidden', !show);
    if (show) visible++;
  }
  countEl.textContent = visible + ' row' + (visible !== 1 ? 's' : '');"""
    js_default_sort  = """
  const sevOrder    = {Critical:4, Important:3, Moderate:2, Low:1, Unknown:0};
  const statusOrder = {'not-fixed':3, 'not-found':2, 'no-package-data':2, 'fix-unknown':1, fixed:0, na:-1};
  const rows = Array.from(tbody.rows);
  rows.sort((a, b) => {
    const sd = (sevOrder[b.dataset.severity] || 0) - (sevOrder[a.dataset.severity] || 0);
    if (sd !== 0) return sd;
    return (statusOrder[b.dataset.status] || 0) - (statusOrder[a.dataset.status] || 0);
  });
  rows.forEach(r => tbody.appendChild(r));"""


html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>{CSS}</style>
</head>
<body>

<div class="header">
  <h1>{title}</h1>
  <div class="sub">{subtitle}</div>
</div>

<div class="main">

  <div class="cards {cards_class}">{cards_html}</div>

  {action_html}

  <div class="filters">
    {filters_html}
  </div>

  <div class="table-wrap">
    <table id="cve-table">
      <thead>{thead_html}</thead>
      <tbody id="cve-tbody">
{tbody_html}
      </tbody>
    </table>
  </div>

  <div class="footer">
    Full machine-readable data: <code>{data_ref}</code>
  </div>

</div>

<script>
const tbody = document.getElementById('cve-tbody');
const countEl = document.getElementById('row-count');
let sortCol = -1, sortAsc = true;

function applyFilters() {{
  {js_filter}
}}

function sortTable(col) {{
  const ths = document.querySelectorAll('thead th[data-col]');
  if (sortCol === col) {{ sortAsc = !sortAsc; }}
  else {{ sortCol = col; sortAsc = true; }}
  ths.forEach(th => {{
    th.classList.remove('sorted-asc', 'sorted-desc');
    if (parseInt(th.dataset.col) === col) th.classList.add(sortAsc ? 'sorted-asc' : 'sorted-desc');
  }});
  const rows = Array.from(tbody.rows);
  rows.sort((a, b) => {{
    const av = a.cells[col].textContent.trim();
    const bv = b.cells[col].textContent.trim();
    return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
  }});
  rows.forEach(r => tbody.appendChild(r));
}}

(function () {{
  {js_default_sort}
}})();

applyFilters();
</script>
</body>
</html>
"""

out_path = "cve-data/cve-report.html"
with open(out_path, "w") as f:
    f.write(html)

print(f"Report written to {out_path}", file=sys.stderr)
print(f"Open with: open {out_path}  (macOS)  or  xdg-open {out_path}  (Linux)", file=sys.stderr)
