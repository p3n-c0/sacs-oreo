# Security Engineering Standard

SACS Oreo is security software. Every change should be designed, reviewed, and tested with that in mind. This document defines the baseline engineering discipline for keeping Oreo safe, credible, and useful for authorized assessment work.

## Core Principles

Oreo should help defenders understand risk without creating unnecessary risk for the systems being assessed.

- Authorization comes first. Features must preserve clear operator responsibility and visible scan intent.
- Safe defaults are mandatory. Passive and safe behavior should be easier to use than aggressive behavior.
- Assessment behavior must be explainable. A maintainer should be able to describe what each check sends, observes, stores, and reports.
- Evidence must be useful but restrained. Capture enough to reproduce and validate findings without needlessly storing secrets or personal data.
- False positives are a security risk. Noisy findings reduce trust and can cause teams to ignore real issues.
- Oreo prioritizes exposure analysis, misconfiguration detection, evidence-based reporting, and remediation guidance over exploit automation.

## Threat Model For Oreo Changes

Before adding or changing a feature, consider how it could fail or be misused.

Key questions:

- Could this send unexpected traffic, payloads, or request volume to a target?
- Could this cross the authorized host, scheme, port, path, or organization scope?
- Could this store credentials, session tokens, API keys, personal data, or sensitive response bodies in reports or logs?
- Could this render untrusted target content into HTML reports without escaping?
- Could a crafted config file, URL, header, cookie, response, or report field trigger unsafe behavior?
- Could the feature make high-confidence claims from weak evidence?
- Could this dependency or parser introduce unsafe loading, code execution, path traversal, or network behavior?

If the answer is yes or unclear, the feature needs additional controls, tests, documentation, or a safer design.

## Input Handling

All external input is untrusted, including CLI arguments, config files, target URLs, HTTP responses, forms, cookies, headers, robots.txt, sitemap.xml, and future plugin output.

Rules:

- Normalize and validate URLs before use.
- Keep crawler scope explicit and same-host unless a future feature intentionally expands scope with visible authorization controls.
- Parse structured data with safe parsers. Do not use unsafe YAML loaders or dynamic evaluation.
- Treat config values as data, not commands.
- Validate numeric limits such as `max_pages`, `timeout`, `crawl_delay`, and `requests_per_second` before they affect scan behavior.
- Keep custom headers and cookies operator-supplied only. Do not invent authentication material.

## HTTP Safety

Oreo must make request behavior predictable.

Rules:

- Default to bounded crawling and controlled request pacing.
- Preserve scan modes: `passive`, `safe`, and future `active` behavior must remain visibly distinct.
- Passive mode must not send validation payloads or extra probe requests.
- Safe mode may use harmless validation probes only when they are documented and non-destructive.
- Do not add brute force, credential attacks, authentication bypass, exploit chaining, destructive payloads, or denial-of-service behavior.
- Any future active behavior must be separately gated, documented, rate-limited, and tested before release.

## Evidence And Reporting Safety

Reports are part of the product attack surface. They must be safe to open and safe to share within an authorized team.

Rules:

- Escape all untrusted content before rendering HTML.
- Avoid embedding raw response bodies unless there is a strong reason and a size limit.
- Prefer concise evidence snippets, status codes, headers, URLs, and reproducible request metadata.
- Redact or avoid storing obvious secrets such as API keys, tokens, passwords, private keys, and session cookies.
- Keep findings structured so JSON, HTML, dashboards, and future integrations use the same data contract.
- Include severity, confidence, reproducibility, OWASP mapping where applicable, business impact, and remediation guidance.
- Be careful with Africa and Nigeria SME impact text: make it practical, specific, and human, without fearmongering.

## Dependency Discipline

Dependencies should earn their place.

Rules:

- Prefer the Python standard library when it is safe and sufficient.
- Add third-party packages only when they materially improve safety, correctness, or maintainability.
- Use safe APIs from dependencies, such as `yaml.safe_load` for YAML.
- Keep dependency versions compatible with the supported Python matrix.
- After dependency changes, verify editable install and the full test suite.
- Watch for dependency behavior that performs unexpected network access, dynamic imports, unsafe deserialization, or shell execution.

## File And Path Safety

Oreo writes reports and may later write evidence artifacts. File handling must be boring and predictable.

Rules:

- Write only to operator-selected output directories or documented defaults.
- Do not write outside the project or output path through unsanitized target-controlled names.
- Avoid using target URLs directly as filesystem paths without sanitization.
- Keep generated reports, scan outputs, captures, screenshots, and evidence out of Git by default.
- Never commit secrets, live credentials, customer data, or private scan results.

## Finding Quality

A finding is not just a string in a report. It is a claim Oreo makes about a target.

Rules:

- Evidence must support the title and severity.
- Confidence should reflect how direct the observation is.
- Reproducibility should explain how stable or repeatable the observation is.
- Severity should consider exploitability, business impact, exposure, and confidence.
- Avoid upgrading severity based only on generic best-practice language.
- Prefer fewer, better findings over noisy output.
- Group or deduplicate repeated evidence when the same issue appears across many URLs.

## Pre-Merge Security Checklist

Use this before merging feature work into `dev`.

- The feature preserves authorization-first behavior.
- Scan mode behavior is clear and tested where relevant.
- Request volume and scope are bounded.
- Untrusted input is parsed safely and validated.
- HTML report output escapes untrusted content.
- JSON output remains structured and stable.
- Sensitive evidence is avoided or redacted where practical.
- Findings include useful evidence, severity, confidence, reproducibility, and remediation.
- Dependencies are minimal, justified, and compatible with Python 3.10, 3.11, and 3.12.
- Unit tests cover normal behavior and at least one failure or edge case.
- Local tests pass before pushing.
- GitHub Actions pass before merging.

## Red Lines

The following do not belong in Oreo unless the project intentionally changes policy and adds strong safeguards:

- credential stuffing or password guessing
- brute-force login attempts
- authentication bypass automation
- destructive payloads
- exploit chaining against live targets
- denial-of-service tests
- stealth, evasion, or persistence features
- automatic data extraction from sensitive files beyond minimal evidence needed for a finding

Oreo should become powerful because it is careful, reproducible, and trusted. That is a stronger foundation than becoming another exploit launcher.
