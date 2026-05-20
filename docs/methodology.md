# SACS Oreo Methodology

This document explains how Oreo approaches authorized web application security assessment. It is part technical guide, part operating principle. The goal is simple: produce findings that are useful, explainable, and defensible without turning Oreo into an exploit launcher.

## Assessment Philosophy

Oreo is built around minimally invasive testing. It prioritizes exposure analysis, misconfiguration detection, evidence collection, and clear reporting over aggressive exploitation.

A good Oreo finding should answer four questions:

- What did Oreo observe?
- Why does it matter?
- How confident is the tool?
- What should the owner fix next?

This is especially important for Nigerian and African SMEs, where a single unclear report can create confusion, panic, or wasted engineering time. Oreo should help teams make better decisions, not bury them in noisy alerts.

## Authorization First

Oreo must only be used against systems where the operator has explicit authorization. The operator is responsible for ensuring the scan target, timing, scope, and testing mode are permitted.

Unauthorized scanning may violate applicable laws, regulations, contracts, platform policies, or acceptable-use rules.

## Scan Modes

Oreo uses explicit scan modes so testing intensity is visible and intentional.

### Passive

Passive mode crawls the target and analyzes observed responses. It does not submit validation payloads or perform extra injection-style probes.

Typical passive checks include:

- response headers
- cookies
- HTTPS usage
- discovered forms
- status codes
- visible technologies
- directory listing indicators seen during crawling

Use passive mode when the operator wants a low-touch review or when the scope is still being clarified.

### Safe

Safe mode includes passive checks plus harmless validation probes. These probes are designed to confirm common exposure and reflection signals without destructive behavior.

Examples include:

- checking well-known public file paths such as `robots.txt` and `sitemap.xml`
- checking common sensitive file names using read-only requests
- using harmless reflected-input markers
- using non-destructive SQL error probes

Safe mode is the default direction for Oreo's early development.

### Active

Active mode is reserved for controlled authorized testing. In the current MVP, active mode is constrained to the same safe checks as safe mode.

Future active-mode work must remain bounded, rate-controlled, and evidence-driven. Active mode should not become a place for brute force, credential attacks, denial-of-service behavior, authentication bypass automation, or destructive payloads.

## Repeatable Scans

Repeatable scans should be configured through a file whenever the same target needs to be reviewed more than once. This reduces operator error and makes results easier to compare over time.

Config files may define:

- target
- scan mode
- scan profile
- max pages
- timeout
- output directory
- crawl delay
- request rate
- custom headers
- custom cookies
- proxy URL

CLI options may override config values for one-off adjustments.
## Transport Controls

Repeatable scan settings should be enforced by the scanner transport, not only stored in config files.

Oreo applies:

- custom headers to crawler and probe requests
- custom cookies through the Cookie header unless the operator provides a Cookie header manually
- proxy settings for HTTP and HTTPS requests
- crawl delay before subsequent requests
- request-rate limits using the slowest configured interval

These controls help authorized operators avoid accidental noisy scans and make scan behavior easier to reproduce.
## What Oreo Does Not Do

Oreo does not aim to be an exploit launcher.

The project should avoid:

- brute forcing
- credential stuffing
- password spraying
- destructive payloads
- denial-of-service behavior
- authentication bypass automation
- exploit chaining for compromise
- unauthorized data extraction
- attempts to evade detection or access controls

Oreo's strength should be clean assessment, low false positives, useful evidence, and business-readable remediation.

## Evidence Collection

Every finding should include direct evidence explaining why it was raised. Evidence should be specific enough for a human reviewer to verify the issue.

Good evidence examples:

- `content-security-policy absent from response headers`
- `Cookie session lacks HttpOnly`
- `.env returned HTTP 200`
- `Response matched a known SQL error pattern`

Poor evidence examples:

- `vulnerable`
- `bad header`
- `looks insecure`
- `possible issue found`

Oreo should prefer short, concrete evidence statements in the main report. Larger proof material, such as request and response captures, should be referenced through `evidence_artifacts` rather than pasted into every finding.

## Request and Response Preservation

Future versions should preserve request and response evidence in a controlled way. The report schema already includes `evidence_artifacts` for this purpose.

Evidence artifacts should eventually include:

- artifact type
- short description
- local relative path
- hash, such as SHA-256
- enough context to reproduce the observation

Sensitive data must be handled carefully. Reports and evidence bundles should avoid storing secrets, credentials, tokens, private customer data, or unnecessary personal data. When preservation is required, Oreo should prefer redaction and hashing.

## Confidence Scoring

Confidence describes how likely the finding is to be valid based on the evidence Oreo collected.

### High Confidence

Use high confidence when the evidence is direct and stable.

Examples:

- a missing response header
- a cookie missing a specific attribute
- a base URL using HTTP
- a public file returning HTTP 200 with content

### Medium Confidence

Use medium confidence when the evidence strongly suggests an issue but still needs human review.

Examples:

- reflected input marker found in a response
- SQL error pattern detected
- directory listing pattern detected
- CORS behavior observed from a crafted Origin request

### Low Confidence

Use low confidence when the signal is weak, contextual, or likely to need manual validation. Oreo should avoid raising low-confidence findings unless the report clearly explains the uncertainty.

## Reproducibility

Reproducibility explains how repeatable the observation is.

### Reproducible

The issue is expected to appear consistently when the same request is made again. Missing headers and cookie attributes usually belong here.

### Observed Once

The issue was observed in one scan path or one probe response. Many validation probes begin here until Oreo supports repeated confirmation.

### Unconfirmed

The issue is a weak signal or a clue for manual review. Oreo should use this sparingly.

## Severity Classification

Severity describes risk, not embarrassment. A finding should not be made High just because it looks scary.

Oreo currently uses:

- Informational
- Low
- Medium
- High
- Critical

Severity should consider:

- exposure of sensitive data
- likelihood of exploitation
- impact on customer accounts
- impact on payments or business operations
- whether authentication is involved
- whether the finding affects a public route
- whether the evidence is direct or inferred

Critical should be rare and reserved for findings with clear, severe business or security impact.

## False-Positive Handling

False positives damage trust. Oreo should prefer fewer, stronger findings over long noisy reports.

To reduce false positives:

- keep finding logic narrow
- store confidence separately from severity
- record reproducibility separately from confidence
- include concrete evidence for every finding
- avoid vague titles and vague remediation
- deduplicate findings by stable ID, URL, and evidence
- avoid claiming exploitability when Oreo only observed exposure
- make uncertain findings easy to identify

If a finding needs manual validation, the report should say so through confidence and reproducibility rather than overstating certainty.

## Business Impact Lens

Oreo reports include business impact written for owners and operators, not only engineers.

The impact language should be practical and human. It should explain how a weakness can affect:

- customer trust
- launch readiness
- personal data handling
- school, NGO, clinic, fintech, e-commerce, and service-business workflows
- account safety
- payments and forms
- reputation

The tone should be calm and useful. Avoid fear-driven language.

## Remediation Guidance

Recommendations should be specific enough to guide the next engineering step.

Good remediation:

- `Set HttpOnly on session and sensitive cookies to limit script access.`
- `Use parameterized queries and suppress detailed database errors in HTTP responses.`

Weak remediation:

- `Fix security.`
- `Harden the app.`
- `Sanitize everything.`

Oreo should eventually support framework-specific remediation, but generic guidance should remain accurate and safe.

## Contributor Expectations

Contributors should preserve Oreo's assessment philosophy.

New checks should include:

- stable finding ID
- clear title
- severity
- confidence
- reproducibility
- category
- OWASP mapping where applicable
- evidence wording
- business impact
- recommendation
- tests

Checks that introduce aggressive behavior, destructive actions, auth abuse, brute force, or denial-of-service risk should not be accepted.
