# SACS Oreo

SACS Oreo is a Python CLI for authorized web application security assessment, created for SecureAfrica Cyber Solutions. This repository currently contains the first MVP variant of Oreo: a safe, authorization-gated scanner that crawls a target web application, collects useful evidence, runs non-destructive checks, and generates JSON and HTML reports.

> Legal notice: use Oreo only on systems you own or have explicit written authorization to test. This MVP does not perform brute force, credential attacks, authentication bypass, exploit chaining, denial-of-service behavior, or destructive payload execution.

## Current Stage

Oreo is at **MVP / Variant 1** stage. It is suitable as a foundation for a professional web application vulnerability analyzer, but it is not yet a mature replacement for a full assessment platform.

## Features

- Same-host crawling from a user-provided base URL
- Legal authorization warning before every scan
- Scan safety modes: passive, safe, active
- Collection of discovered URLs, forms, cookies, response headers, status codes, content types, and basic technology hints
- Safe checks for missing security headers, insecure cookies, HTTP usage, CORS misconfiguration, exposed sensitive files, directory listing, robots.txt, sitemap.xml, harmless reflected input, and SQL error patterns
- Severity labels: Informational, Low, Medium, High, Critical
- Confidence and reproducibility fields for every finding
- Evidence artifact slots for future request/response preservation
- OWASP Top 10 mappings where applicable
- Remediation guidance for every finding
- Nigeria/Africa SME business impact notes in findings
- JSON and HTML report generation
- Unit tests for core URL, crawler, check, and report behavior

## Installation

From the repository root:

```powershell
python -m pip install -e .
```

After installation:

```powershell
sacs-oreo --help
oreo --help
```

## Run From Source

From the repository root:

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m sacs_oreo --help
```

If your Windows `python` launcher points to the Microsoft Store shim, use your installed Python path instead.

## Scan Safety Modes

Oreo supports explicit scan safety modes so operators can choose the level of interaction appropriate for an authorized assessment:

- `passive`: crawl and analyze observed responses without validation payloads or extra probe requests
- `safe`: run passive analysis plus harmless validation probes for common exposure and injection signals
- `active`: reserved for controlled authorized testing; currently constrained to the same safe checks as `safe`

## Example Scan

```powershell
sacs-oreo scan https://example.com --mode safe `
  --max-pages 30 `
  --timeout 8 `
  --output-dir reports/example `
  --i-have-authorization
```

Reports are written to the selected output directory:

- `oreo-report.json`
- `oreo-report.html`

## Finding Schema

Oreo findings use a stable structured format so JSON reports, HTML reports, dashboards, APIs, and future integrations can share the same data contract:

```json
{
  "id": "OREO-001",
  "title": "Missing Content Security Policy",
  "severity": "Medium",
  "confidence": "High",
  "reproducibility": "Reproducible",
  "category": "Security Headers",
  "owasp": "A05:2021",
  "affected_url": "https://example.com/",
  "evidence": "content-security-policy absent from response headers",
  "evidence_artifacts": [],
  "business_impact": "This can make it easier for a successful script injection issue to affect customers. For fintech, e-commerce, school portals, NGOs, clinics, and member platforms collecting personal data, fix this before public launch or major campaigns.",
  "recommendation": "Add a restrictive Content-Security-Policy header to reduce script injection and data exfiltration risk.",
  "references": []
}
```

Finding definitions are centralized in `src/sacs_oreo/findings.py`.

The `business_impact` field is written for owners and operators, not only engineers. It explains how a weakness can affect customer trust, launch readiness, data handling, or daily operations for SMEs across Nigeria and Africa.

The `confidence`, `reproducibility`, and `evidence_artifacts` fields are designed to reduce false positives and make findings easier to verify. Future versions will use `evidence_artifacts` to reference preserved request and response captures without bloating the main report.

## Tests

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m unittest discover -s tests
```

## Methodology

See [docs/methodology.md](docs/methodology.md) for Oreo's assessment philosophy, evidence model, confidence scoring, reproducibility, and false-positive handling.

## Roadmap

See [ROADMAP.md](ROADMAP.md).

## Security and Responsible Use

See [SECURITY.md](SECURITY.md).
