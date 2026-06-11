#!/usr/bin/env python3
"""Generate a self-contained HTML report from cve-data/verified-cves.json.

All CSS is defined in the <style> block via custom properties — no inline
styles anywhere in the HTML. Dark mode is handled by
@media (prefers-color-scheme: dark) overriding the custom properties.

Reads:  cve-data/verified-cves.json
Writes: cve-data/cve-report.html

All progress goes to stderr. Exits non-zero on failure.
"""
import json
import sys
from datetime import datetime, timezone
from html import escape

try:
    with open("cve-data/verified-cves.json") as f:
        data = json.load(f)
except FileNotFoundError:
    print("Error: cve-data/verified-cves.json not found.", file=sys.stderr)
    sys.exit(1)
except json.JSONDecodeError as e:
    print(f"Error: invalid JSON: {e}", file=sys.stderr)
    sys.exit(1)

verification  = data.get("verification", {})
images        = verification.get("images", {})
skipped_nvras = verification.get("skipped_nvras", {})
vsummary      = data.get("verification_summary", {})
cves          = data.get("cves", [])
verified_at   = data.get("verified_at", "unknown")

SEVERITY_ORDER = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1, "Unknown": 0}


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

  /* ── Action-required banner ──────────────────────────────────────────── */
  .action-required {
    background: var(--action-bg);
    border: 2px solid var(--action-border);
    border-radius: 0.75rem;
    padding: 1.25rem;
    margin-bottom: 2rem;
  }
  .action-required h2 { color: var(--action-heading); font-size: 1rem; margin-bottom: 0.75rem; }
  .action-required h3 { color: var(--action-heading); font-size: 0.875rem; margin: 0.75rem 0 0.4rem; }
  .action-required p  { font-size: 0.875rem; color: var(--action-text); margin-bottom: 0.5rem; }
  .action-required ul { list-style: disc; padding-left: 1.25rem; font-size: 0.875rem; color: var(--action-text); }
  .action-required li { margin: 0.3rem 0; }
  .action-required a  { color: var(--action-link); }

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


rows = make_rows(cves, images)

any_skipped      = {c: lines for c, lines in skipped_nvras.items() if lines}
not_found_rows   = [r for r in rows if r["status_key"] == "not-found"]
no_pkg_data_rows = [r for r in rows if r["status_key"] == "no-package-data"]


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


# ── Assemble HTML ─────────────────────────────────────────────────────────────

container_options = "\n".join(
    f'<option value="{c.split("/")[-1]}">{c.split("/")[-1]}</option>'
    for c in images
)

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CVE Build Verification Report</title>
<style>{CSS}</style>
</head>
<body>

<div class="header">
  <h1>CVE Build Verification Report</h1>
  <div class="sub">Generated {escape(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))}
  &nbsp;·&nbsp; Data verified at: {escape(verified_at[:19].replace("T", " "))} UTC</div>
</div>

<div class="main">

  <div class="cards">{summary_cards_html()}</div>

  {action_required_html()}

  <div class="filters">
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
    <span class="row-count" id="row-count"></span>
  </div>

  <div class="table-wrap">
    <table id="cve-table">
      <thead>
        <tr>
          <th onclick="sortTable(0)">CVE ID</th>
          <th onclick="sortTable(1)">Severity</th>
          <th onclick="sortTable(2)">Container</th>
          <th onclick="sortTable(3)">Status</th>
          <th onclick="sortTable(4)">Installed</th>
          <th onclick="sortTable(5)">Minimum Fixed</th>
        </tr>
      </thead>
      <tbody id="cve-tbody">
{table_rows_html()}
      </tbody>
    </table>
  </div>

  <div class="footer">
    Full machine-readable data: <code>cve-data/verified-cves.json</code>
  </div>

</div>

<script>
const tbody = document.getElementById('cve-tbody');
const countEl = document.getElementById('row-count');
let sortCol = -1, sortAsc = true;

function applyFilters() {{
  const container = document.getElementById('f-container').value;
  const status    = document.getElementById('f-status').value;
  const severity  = document.getElementById('f-severity').value;
  const search    = document.getElementById('f-search').value.toLowerCase();
  let visible = 0;
  for (const tr of tbody.rows) {{
    const show =
      (!container || tr.dataset.container === container) &&
      (!status    || tr.dataset.status    === status)    &&
      (!severity  || tr.dataset.severity  === severity)  &&
      (!search    || tr.cells[0].textContent.toLowerCase().includes(search));
    tr.classList.toggle('hidden', !show);
    if (show) visible++;
  }}
  countEl.textContent = visible + ' row' + (visible !== 1 ? 's' : '');
}}

function sortTable(col) {{
  const ths = document.querySelectorAll('thead th');
  if (sortCol === col) {{ sortAsc = !sortAsc; }}
  else {{ sortCol = col; sortAsc = true; }}
  ths.forEach((th, i) => {{
    th.classList.remove('sorted-asc', 'sorted-desc');
    if (i === col) th.classList.add(sortAsc ? 'sorted-asc' : 'sorted-desc');
  }});
  const rows = Array.from(tbody.rows);
  rows.sort((a, b) => {{
    const av = a.cells[col].textContent.trim();
    const bv = b.cells[col].textContent.trim();
    return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
  }});
  rows.forEach(r => tbody.appendChild(r));
}}

/* Default sort: severity desc, then unfixed-first */
(function () {{
  const sevOrder    = {{Critical:4, Important:3, Moderate:2, Low:1, Unknown:0}};
  const statusOrder = {{'not-fixed':3, 'not-found':2, 'no-package-data':2, 'fix-unknown':1, fixed:0, na:-1}};
  const rows = Array.from(tbody.rows);
  rows.sort((a, b) => {{
    const sd = (sevOrder[b.dataset.severity] || 0) - (sevOrder[a.dataset.severity] || 0);
    if (sd !== 0) return sd;
    return (statusOrder[b.dataset.status] || 0) - (statusOrder[a.dataset.status] || 0);
  }});
  rows.forEach(r => tbody.appendChild(r));
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
print(f"Open with: open {out_path}", file=sys.stderr)
