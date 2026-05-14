#!/usr/bin/env python3
"""
VulnSec - HTML Report Generator
Reads findings.json and produces a self-contained HTML report.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "#E24B4A",
    "HIGH": "#EF9F27",
    "MEDIUM": "#378ADD",
    "LOW": "#639922",
    "INFO": "#7F77DD",
}


def generate_report(findings_file: str = "findings.json", output: str = "report.html"):
    with open(findings_file) as f:
        findings = json.load(f)

    findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 99))

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

    rows = ""
    for i, f in enumerate(findings):
        sev = f.get("severity", "INFO")
        color = SEVERITY_COLOR.get(sev, "#888")
        rows += f"""
        <tr>
          <td style="font-family:monospace;font-size:12px;color:#888">VLN-{i+1:04d}</td>
          <td style="font-weight:600">{f.get('vuln_type','')}</td>
          <td style="font-family:monospace;font-size:11px;word-break:break-all">{f.get('url','')}</td>
          <td style="font-family:monospace;font-size:11px">{f.get('parameter','')}</td>
          <td><span style="background:{color}22;color:{color};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">{sev}</span></td>
          <td style="font-weight:600;color:{color}">{f.get('cvss_score','')}</td>
          <td style="font-family:monospace;font-size:11px;color:#555">{f.get('owasp_category','')}</td>
          <td style="font-size:12px;color:#666">{f.get('description','')[:80]}...</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnSec Scan Report</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f8f9fa;color:#1a1a1a}}
  .header{{background:#1a1a2e;color:#fff;padding:2rem 3rem}}
  .header h1{{font-size:2rem;margin:0 0 .25rem}}
  .header p{{opacity:.6;margin:0;font-family:monospace}}
  .container{{max-width:1400px;margin:2rem auto;padding:0 2rem}}
  .cards{{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:2rem}}
  .card{{background:#fff;border-radius:8px;padding:1.25rem;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  .card-label{{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#888;margin-bottom:.5rem}}
  .card-val{{font-size:2rem;font-weight:800;font-family:monospace}}
  table{{width:100%;background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.08);border-collapse:collapse;overflow:hidden}}
  th{{padding:.75rem 1rem;background:#f1f3f5;font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:#555;text-align:left;border-bottom:1px solid #e9ecef}}
  td{{padding:.65rem 1rem;border-bottom:1px solid #f1f3f5;font-size:13px;vertical-align:middle}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#fafbfc}}
  .footer{{text-align:center;padding:2rem;color:#888;font-size:12px}}
</style>
</head>
<body>
<div class="header">
  <h1>VulnSec Scan Report</h1>
  <p>Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} &nbsp;|&nbsp; Total Findings: {len(findings)}</p>
</div>
<div class="container">
  <div class="cards">
    {''.join(f'<div class="card"><div class="card-label">{s}</div><div class="card-val" style="color:{SEVERITY_COLOR[s]}">{counts.get(s,0)}</div></div>' for s in SEVERITY_ORDER)}
  </div>
  <table>
    <thead><tr><th>ID</th><th>Vulnerability</th><th>URL</th><th>Parameter</th><th>Severity</th><th>CVSS</th><th>OWASP</th><th>Description</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">VulnSec — For authorised security testing only</div>
</body>
</html>"""

    with open(output, "w") as f:
        f.write(html)
    print(f"Report saved → {output}")


if __name__ == "__main__":
    inp = sys.argv[1] if len(sys.argv) > 1 else "findings.json"
    out = sys.argv[2] if len(sys.argv) > 2 else "report.html"
    generate_report(inp, out)
