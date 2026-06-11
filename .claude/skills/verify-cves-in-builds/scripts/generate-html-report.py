#!/usr/bin/env python3
"""Generate a self-contained HTML report from cve-data/verified-cves.json.

All CSS and JavaScript are inlined — no external dependencies, works offline.

Reads:  cve-data/verified-cves.json
Writes: cve-data/cve-report.html

All progress goes to stderr. Exits non-zero on failure.
"""
import json
import sys
from datetime import datetime, timezone
from html import escape

try:
    data = json.load(open("cve-data/verified-cves.json"))
except FileNotFoundError:
    print("Error: cve-data/verified-cves.json not found.", file=sys.stderr)
    sys.exit(1)
except json.JSONDecodeError as e:
    print(f"Error: invalid JSON: {e}", file=sys.stderr)
    sys.exit(1)

verification   = data.get("verification", {})
images         = verification.get("images", {})
skipped_nvras  = verification.get("skipped_nvras", {})
vsummary       = data.get("verification_summary", {})
cves           = data.get("cves", [])
verified_at    = data.get("verified_at", "unknown")

SEVERITY_COLOR = {
    "Critical":  "#dc2626",
    "Important": "#ea580c",
    "Moderate":  "#ca8a04",
    "Low":       "#2563eb",
    "Unknown":   "#6b7280",
}
STATUS_COLOR = {
    "fixed":           "#16a34a",
    "not_fixed":       "#dc2626",
    "not_found":       "#7c3aed",
    "fix_unknown":     "#ca8a04",
    "no_package_data": "#b45309",   # amber — affects container, but no RPM data
    "n_a":             "#9ca3af",
}

def sev_color(s):
    return SEVERITY_COLOR.get(s, "#6b7280")

def badge(text, color, title=""):
    t = f' title="{escape(title)}"' if title else ""
    return (f'<span{t} style="display:inline-block;padding:2px 8px;border-radius:9999px;'
            f'font-size:0.75rem;font-weight:600;color:#fff;background:{color}">{escape(str(text))}</span>')


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
            entry = checked.get(container, {})
            is_fixed      = entry.get("is_fixed")
            pkg_found     = entry.get("package_found", False)
            searched      = entry.get("searched_names", [])
            installed     = entry.get("installed_nvras", [])
            minimum_fixed = entry.get("minimum_fixed_nvr") or ""

            if container not in affected:
                status_key = "n_a"
                status_label = "N/A"
            elif is_fixed is True:
                status_key = "fixed"
                status_label = "Fixed"
            elif is_fixed is False:
                status_key = "not_fixed"
                status_label = "Not Fixed"
            elif pkg_found and is_fixed is None:
                status_key = "fix_unknown"
                status_label = "Fix Unknown"
            elif not pkg_found and searched:
                status_key = "not_found"
                status_label = "Not Found"
            elif not pkg_found and not searched:
                # CVE affects this container but no RPM package name is available
                # to search for — may be a non-RPM dependency (npm, Python, etc.)
                # Cannot be verified automatically; requires manual investigation.
                status_key = "no_package_data"
                status_label = "UNKNOWN"
            else:
                status_key = "n_a"
                status_label = "N/A"

            rows.append({
                "cve_id": cve_id,
                "cve_link": cve_link,
                "severity": severity,
                "sev_order": {"Critical":4,"Important":3,"Moderate":2,"Low":1}.get(severity,0),
                "container": container,
                "container_short": container.split("/")[-1],
                "status_key": status_key,
                "status_label": status_label,
                "installed": ", ".join(installed) if installed else "",
                "minimum_fixed": minimum_fixed,
                "searched": ", ".join(searched) if searched else "",
                "checked_image": entry.get("checked_image", ""),
            })
    return rows

rows = make_rows(cves, images)

# ── Any action-required items? ────────────────────────────────────────────────
any_skipped        = {c: lines for c, lines in skipped_nvras.items() if lines}
not_found_cves     = [r for r in rows if r["status_key"] == "not_found"]
no_pkg_data_cves   = [r for r in rows if r["status_key"] == "no_package_data"]


# ── HTML generation ───────────────────────────────────────────────────────────

def summary_card(container, s, image):
    short = container.split("/")[-1]
    total = s.get("found", 0) + s.get("not_found", 0)
    return f"""
    <div class="card">
      <div class="card-title">{escape(short)}</div>
      <div class="card-image">{escape(image)}</div>
      <div class="stat-grid">
        <div class="stat" style="color:{STATUS_COLOR['not_fixed']}">
          <span class="stat-n">{s.get('not_fixed',0)}</span>
          <span class="stat-l">Not Fixed</span>
        </div>
        <div class="stat" style="color:{STATUS_COLOR['fixed']}">
          <span class="stat-n">{s.get('fixed',0)}</span>
          <span class="stat-l">Fixed</span>
        </div>
        <div class="stat" style="color:{STATUS_COLOR['not_found']}">
          <span class="stat-n">{s.get('not_found',0)}</span>
          <span class="stat-l">Not Found</span>
        </div>
        <div class="stat" style="color:{STATUS_COLOR['no_package_data']}">
          <span class="stat-n">{s.get('no_package_data',0)}</span>
          <span class="stat-l">UNKNOWN</span>
        </div>
      </div>
    </div>"""


def action_required_section():
    if not any_skipped and not not_found_cves and not no_pkg_data_cves:
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

    if not_found_cves:
        parts.append("<h3>CVEs whose packages were not found in the container</h3>")
        parts.append("<p>These CVEs affect the container according to published data, "
                     "but the vulnerable package was not found in the RPM list. "
                     "Verify manually.</p><ul>")
        seen = set()
        for r in sorted(not_found_cves, key=lambda x: -x["sev_order"]):
            key = (r["cve_id"], r["container_short"])
            if key in seen:
                continue
            seen.add(key)
            parts.append(f"<li>{badge(r['severity'], sev_color(r['severity']))} "
                         f'<a href="{escape(r["cve_link"])}" target="_blank">{escape(r["cve_id"])}</a> '
                         f'— {escape(r["container_short"])} '
                         f'(searched for: <code>{escape(r["searched"])}</code>)</li>')
        parts.append("</ul>")

    if no_pkg_data_cves:
        parts.append("<h3>CVEs marked UNKNOWN — no RPM package data available</h3>")
        parts.append("<p>These CVEs are reported as affecting the container, but no RPM "
                     "package name could be determined from the available data. They cannot "
                     "be verified automatically. The vulnerable component may be a non-RPM "
                     "dependency (e.g. npm, Python). <strong>Investigate each one manually.</strong></p><ul>")
        seen = set()
        for r in sorted(no_pkg_data_cves, key=lambda x: -x["sev_order"]):
            key = (r["cve_id"], r["container_short"])
            if key in seen:
                continue
            seen.add(key)
            parts.append(f"<li>{badge(r['severity'], sev_color(r['severity']))} "
                         f'<a href="{escape(r["cve_link"])}" target="_blank">{escape(r["cve_id"])}</a> '
                         f'— {escape(r["container_short"])}</li>')
        parts.append("</ul>")

    parts.append("</div>")
    return "\n".join(parts)


def table_rows_html(rows):
    parts = []
    for r in rows:
        sc   = sev_color(r["severity"])
        stc  = STATUS_COLOR.get(r["status_key"], "#9ca3af")
        parts.append(
            f'<tr data-status="{r["status_key"]}" data-container="{r["container_short"]}" '
            f'data-severity="{r["severity"]}">'
            f'<td><a href="{escape(r["cve_link"])}" target="_blank">{escape(r["cve_id"])}</a></td>'
            f'<td>{badge(r["severity"], sc)}</td>'
            f'<td><code style="font-size:0.8em">{escape(r["container_short"])}</code></td>'
            f'<td>{badge(r["status_label"], stc)}</td>'
            f'<td><code style="font-size:0.8em">{escape(r["installed"])}</code></td>'
            f'<td><code style="font-size:0.8em">{escape(r["minimum_fixed"])}</code></td>'
            f'</tr>'
        )
    return "\n".join(parts)


container_options = "\n".join(
    f'<option value="{c.split("/")[-1]}">{c.split("/")[-1]}</option>'
    for c in images
)

cards_html = "\n".join(
    summary_card(c, vsummary.get(c, {}), images.get(c, ""))
    for c in images
)

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CVE Build Verification Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
        background:#f8fafc;color:#1e293b;line-height:1.5}}
  .header{{background:#0f172a;color:#f8fafc;padding:1.5rem 2rem}}
  .header h1{{font-size:1.5rem;font-weight:700}}
  .header .sub{{font-size:0.85rem;color:#94a3b8;margin-top:0.25rem}}
  .main{{padding:2rem;max-width:1400px;margin:0 auto}}
  .cards{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}}
  .card{{background:#fff;border:1px solid #e2e8f0;border-radius:0.75rem;
         padding:1.25rem;min-width:260px;flex:1}}
  .card-title{{font-weight:700;font-size:1rem;margin-bottom:0.25rem}}
  .card-image{{font-size:0.75rem;color:#64748b;margin-bottom:1rem;
               white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
  .stat-grid{{display:grid;grid-template-columns:1fr 1fr;gap:0.5rem}}
  .stat{{text-align:center;padding:0.5rem;background:#f8fafc;border-radius:0.5rem}}
  .stat-n{{display:block;font-size:1.5rem;font-weight:700}}
  .stat-l{{display:block;font-size:0.7rem;font-weight:500;text-transform:uppercase;
            letter-spacing:0.05em;color:#64748b}}
  .action-required{{background:#fef2f2;border:2px solid #fca5a5;border-radius:0.75rem;
                    padding:1.25rem;margin-bottom:2rem}}
  .action-required h2{{color:#b91c1c;font-size:1rem;margin-bottom:0.75rem}}
  .action-required h3{{color:#991b1b;font-size:0.875rem;margin:0.75rem 0 0.4rem}}
  .action-required p{{font-size:0.875rem;color:#7f1d1d;margin-bottom:0.5rem}}
  .action-required ul{{list-style:disc;padding-left:1.25rem;font-size:0.875rem;color:#7f1d1d}}
  .action-required li{{margin:0.3rem 0}}
  .action-required a{{color:#b91c1c}}
  .filters{{display:flex;gap:0.75rem;flex-wrap:wrap;align-items:center;
             margin-bottom:1rem;padding:1rem;background:#fff;
             border:1px solid #e2e8f0;border-radius:0.75rem}}
  .filters label{{font-size:0.8rem;font-weight:600;color:#475569}}
  select,input{{border:1px solid #cbd5e1;border-radius:0.4rem;padding:0.35rem 0.6rem;
                font-size:0.85rem;background:#fff;color:#1e293b}}
  .count{{font-size:0.8rem;color:#64748b;margin-left:auto}}
  .table-wrap{{overflow-x:auto;background:#fff;border:1px solid #e2e8f0;
               border-radius:0.75rem}}
  table{{width:100%;border-collapse:collapse;font-size:0.875rem}}
  thead th{{background:#f1f5f9;padding:0.75rem 1rem;text-align:left;
             font-weight:600;font-size:0.75rem;text-transform:uppercase;
             letter-spacing:0.05em;color:#475569;position:sticky;top:0;
             cursor:pointer;user-select:none;white-space:nowrap}}
  thead th:hover{{background:#e2e8f0}}
  thead th.sorted-asc::after{{content:" ↑"}}
  thead th.sorted-desc::after{{content:" ↓"}}
  tbody tr{{border-top:1px solid #f1f5f9;transition:background 0.1s}}
  tbody tr:hover{{background:#f8fafc}}
  tbody tr.hidden{{display:none}}
  td{{padding:0.6rem 1rem;vertical-align:middle}}
  td a{{color:#0f172a;text-decoration:none;font-weight:500}}
  td a:hover{{text-decoration:underline}}
  code{{background:#f1f5f9;padding:0.1em 0.3em;border-radius:0.2rem;
        font-family:ui-monospace,monospace}}
  .footer{{text-align:center;font-size:0.75rem;color:#94a3b8;margin-top:2rem;
            padding-bottom:2rem}}
</style>
</head>
<body>

<div class="header">
  <h1>CVE Build Verification Report</h1>
  <div class="sub">Generated {escape(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))}
  &nbsp;·&nbsp; Data verified at: {escape(verified_at[:19].replace("T"," "))} UTC</div>
</div>

<div class="main">

  <div class="cards">{cards_html}</div>

  {action_required_section()}

  <div class="filters">
    <label>Container</label>
    <select id="f-container" onchange="applyFilters()">
      <option value="">All</option>
      {container_options}
    </select>
    <label>Status</label>
    <select id="f-status" onchange="applyFilters()">
      <option value="">All</option>
      <option value="not_fixed">Not Fixed</option>
      <option value="fixed">Fixed</option>
      <option value="not_found">Not Found</option>
      <option value="no_package_data">UNKNOWN (no RPM data)</option>
      <option value="fix_unknown">Fix Unknown</option>
      <option value="n_a">N/A</option>
    </select>
    <label>Severity</label>
    <select id="f-severity" onchange="applyFilters()">
      <option value="">All</option>
      <option value="Critical">Critical</option>
      <option value="Important">Important</option>
      <option value="Moderate">Moderate</option>
      <option value="Low">Low</option>
      <option value="Unknown">Unknown</option>
    </select>
    <input id="f-search" type="search" placeholder="Search CVE ID…"
           oninput="applyFilters()" style="width:160px">
    <span class="count" id="row-count"></span>
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
{table_rows_html(rows)}
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
  ths.forEach((th,i) => {{
    th.classList.remove('sorted-asc','sorted-desc');
    if (i === col) th.classList.add(sortAsc ? 'sorted-asc' : 'sorted-desc');
  }});
  const rows = Array.from(tbody.rows);
  rows.sort((a,b) => {{
    const av = a.cells[col].textContent.trim();
    const bv = b.cells[col].textContent.trim();
    return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
  }});
  rows.forEach(r => tbody.appendChild(r));
}}

// Default sort: severity desc, then status
(function() {{
  const sevOrder = {{Critical:4,Important:3,Moderate:2,Low:1,Unknown:0}};
  const statOrder = {{not_fixed:3,not_found:2,fix_unknown:1,fixed:0,n_a:-1}};
  const rows = Array.from(tbody.rows);
  rows.sort((a,b) => {{
    const sd = (sevOrder[b.dataset.severity]||0) - (sevOrder[a.dataset.severity]||0);
    if (sd !== 0) return sd;
    return (statOrder[b.dataset.status]||0) - (statOrder[a.dataset.status]||0);
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
