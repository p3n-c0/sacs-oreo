from __future__ import annotations

import html
import json
from pathlib import Path

from .models import ScanReport


def write_json_report(report: ScanReport, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return output_path


def write_html_report(report: ScanReport, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    findings_rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(finding.id)}</td>"
        f"<td>{html.escape(finding.severity)}</td>"
        f"<td>{html.escape(finding.category)}</td>"
        f"<td>{html.escape(finding.title)}</td>"
        f"<td><a href=\"{html.escape(finding.affected_url)}\">{html.escape(finding.affected_url)}</a></td>"
        f"<td>{html.escape(finding.owasp or 'N/A')}</td>"
        f"<td>{html.escape(finding.evidence)}</td>"
        f"<td>{html.escape(finding.business_impact)}</td>"
        f"<td>{html.escape(finding.recommendation)}</td>"
        "</tr>"
        for finding in report.findings
    )
    discovered_rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(page.url)}</td>"
        f"<td>{html.escape(str(page.status_code or 'N/A'))}</td>"
        f"<td>{html.escape(page.content_type or 'N/A')}</td>"
        f"<td>{html.escape(', '.join(page.technologies) or 'N/A')}</td>"
        f"<td>{len(page.forms)}</td>"
        f"<td>{len(page.cookies)}</td>"
        "</tr>"
        for page in report.discovered_urls
    )
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SACS Oreo Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; color: #1f2933; }}
    h1, h2 {{ color: #102a43; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }}
    th, td {{ border: 1px solid #d9e2ec; padding: 0.6rem; text-align: left; vertical-align: top; }}
    th {{ background: #f0f4f8; }}
    .meta {{ background: #f8fafc; border: 1px solid #d9e2ec; padding: 1rem; }}
  </style>
</head>
<body>
  <h1>SACS Oreo Security Assessment Report</h1>
  <div class="meta">
    <p><strong>Target:</strong> {html.escape(report.target)}</p>
    <p><strong>Scan mode:</strong> {html.escape(report.scan_mode)}</p>
    <p><strong>Started:</strong> {html.escape(report.started_at)}</p>
    <p><strong>Completed:</strong> {html.escape(report.completed_at)}</p>
    <p><strong>Authorization confirmed:</strong> {report.authorization_confirmed}</p>
    <p><strong>Discovered URLs:</strong> {len(report.discovered_urls)}</p>
    <p><strong>Findings:</strong> {len(report.findings)}</p>
  </div>
  <h2>Findings</h2>
  <table>
    <thead>
      <tr><th>ID</th><th>Severity</th><th>Category</th><th>Title</th><th>URL</th><th>OWASP</th><th>Evidence</th><th>Business Impact</th><th>Recommendation</th></tr>
    </thead>
    <tbody>{findings_rows or '<tr><td colspan="9">No findings recorded.</td></tr>'}</tbody>
  </table>
  <h2>Discovered URLs</h2>
  <table>
    <thead>
      <tr><th>URL</th><th>Status</th><th>Content-Type</th><th>Technologies</th><th>Forms</th><th>Cookies</th></tr>
    </thead>
    <tbody>{discovered_rows or '<tr><td colspan="6">No URLs discovered.</td></tr>'}</tbody>
  </table>
</body>
</html>
"""
    output_path.write_text(document, encoding="utf-8")
    return output_path
