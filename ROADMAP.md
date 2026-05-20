# Roadmap

This roadmap keeps Oreo powerful while preserving an authorized, non-destructive assessment model.

## v0.1.0 - MVP / Variant 1

- Authorization-gated CLI
- Same-host crawler
- Passive response analysis
- Safe checks:
  - security headers
  - cookies
  - HTTPS
  - CORS
  - sensitive files
  - directory listing
  - robots.txt
  - sitemap.xml
  - reflected input
  - SQL error patterns
- JSON report
- HTML report
- Core unit tests

## v0.2.0 - Repeatable Scans

- YAML/TOML config file support
- Scan profiles: quick, standard, deep-safe
- Request rate limiting
- Crawl delay controls
- Custom headers
- Custom cookies
- Proxy support

## v0.3.0 - Professional Reporting

- SACS-branded HTML report
- Finding de-duplication
- Evidence grouping
- Severity scoring refinement
- Remediation guidance
- Executive summary

## v0.4.0 - Engineering Integration

- SARIF export
- GitHub Actions workflow
- Packaged release builds
- Baseline comparison
- Scan diffing

## v0.5.0 - Plugin & Intelligence Layer

- Safe plugin architecture
- Approved safe checks only
- Improved technology fingerprinting
- Safe CVE correlation
- Local vulnerable demo fixtures
