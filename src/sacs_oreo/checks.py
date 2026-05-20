from __future__ import annotations

import re
from urllib.parse import urlsplit
from urllib.request import Request, build_opener

from .crawler import Crawler
from .models import DiscoveredURL, Finding
from .url_utils import add_query_param, normalize_url


SECURITY_HEADERS = {
    "content-security-policy": (
        "Missing Content-Security-Policy header",
        "Medium",
        "OWASP A05:2021 - Security Misconfiguration",
        "Add a restrictive Content-Security-Policy to reduce script injection and data exfiltration risk.",
    ),
    "strict-transport-security": (
        "Missing Strict-Transport-Security header",
        "Medium",
        "OWASP A02:2021 - Cryptographic Failures",
        "Serve the site over HTTPS and set Strict-Transport-Security with an appropriate max-age.",
    ),
    "x-content-type-options": (
        "Missing X-Content-Type-Options header",
        "Low",
        "OWASP A05:2021 - Security Misconfiguration",
        "Set X-Content-Type-Options: nosniff to reduce MIME sniffing risk.",
    ),
    "x-frame-options": (
        "Missing X-Frame-Options header",
        "Low",
        "OWASP A05:2021 - Security Misconfiguration",
        "Set X-Frame-Options or use CSP frame-ancestors to control framing.",
    ),
    "referrer-policy": (
        "Missing Referrer-Policy header",
        "Low",
        "OWASP A01:2021 - Broken Access Control",
        "Set Referrer-Policy to limit sensitive URL leakage through referrer headers.",
    ),
    "permissions-policy": (
        "Missing Permissions-Policy header",
        "Informational",
        "OWASP A05:2021 - Security Misconfiguration",
        "Set Permissions-Policy to explicitly disable browser features the app does not need.",
    ),
}

SENSITIVE_FILES = (
    ".env",
    ".git/config",
    "backup.zip",
    "database.sql",
    "db.sql",
    "backup.sql",
    "config.php.bak",
)

SQL_ERROR_PATTERNS = (
    r"SQL syntax.*MySQL",
    r"Warning.*mysqli?",
    r"PostgreSQL.*ERROR",
    r"ORA-\d{5}",
    r"SQLite/JDBCDriver",
    r"sqlite_error",
    r"Unclosed quotation mark after the character string",
    r"Microsoft OLE DB Provider for SQL Server",
)

XSS_PAYLOAD = "oreo-xss-check-7f4a"
SQL_PROBE = "'"


def check_security_headers(page: DiscoveredURL, base_url: str | None = None) -> list[Finding]:
    present = {key.lower() for key in page.response_headers}
    findings: list[Finding] = []
    for header, (title, severity, owasp, remediation) in SECURITY_HEADERS.items():
        if header == "strict-transport-security" and urlsplit(page.url).scheme != "https":
            continue
        if header not in present:
            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    description=f"The response does not include the {header} security header.",
                    evidence=f"{header} absent from response headers",
                    affected_url=page.url,
                    owasp_category=owasp,
                    remediation=remediation,
                    check_id=f"headers.{header}",
                )
            )
    return findings


def check_cookies(page: DiscoveredURL) -> list[Finding]:
    findings: list[Finding] = []
    is_https = urlsplit(page.url).scheme == "https"
    for cookie in page.cookies:
        attrs = {key.lower(): value for key, value in cookie.attributes.items()}
        if is_https and not attrs.get("secure"):
            findings.append(
                Finding(
                    title="Cookie missing Secure attribute",
                    severity="Medium",
                    description="A cookie set over HTTPS is missing the Secure attribute.",
                    evidence=f"Cookie {cookie.name} lacks Secure",
                    affected_url=page.url,
                    owasp_category="OWASP A02:2021 - Cryptographic Failures",
                    remediation="Set the Secure attribute on cookies that should only be sent over HTTPS.",
                    check_id="cookies.secure",
                )
            )
        if not attrs.get("httponly"):
            findings.append(
                Finding(
                    title="Cookie missing HttpOnly attribute",
                    severity="Low",
                    description="A cookie is accessible to client-side scripts.",
                    evidence=f"Cookie {cookie.name} lacks HttpOnly",
                    affected_url=page.url,
                    owasp_category="OWASP A03:2021 - Injection",
                    remediation="Set HttpOnly on session and sensitive cookies to limit script access.",
                    check_id="cookies.httponly",
                )
            )
        if not attrs.get("samesite"):
            findings.append(
                Finding(
                    title="Cookie missing SameSite attribute",
                    severity="Low",
                    description="A cookie does not define a SameSite policy.",
                    evidence=f"Cookie {cookie.name} lacks SameSite",
                    affected_url=page.url,
                    owasp_category="OWASP A01:2021 - Broken Access Control",
                    remediation="Set SameSite=Lax or SameSite=Strict unless cross-site use is required.",
                    check_id="cookies.samesite",
                )
            )
    return findings


def check_https(base_url: str) -> list[Finding]:
    normalized = normalize_url(base_url)
    if urlsplit(normalized).scheme == "http":
        return [
            Finding(
                title="Target uses HTTP",
                severity="High",
                description="The target base URL uses unencrypted HTTP.",
                evidence=normalized,
                affected_url=normalized,
                owasp_category="OWASP A02:2021 - Cryptographic Failures",
                remediation="Serve the application over HTTPS and redirect HTTP traffic to HTTPS.",
                check_id="https.plaintext",
            )
        ]
    return []


def check_directory_listing(page: DiscoveredURL) -> list[Finding]:
    body = getattr(page, "_body", "")
    if page.status_code == 200 and re.search(r"<title>Index of /|Index of /", body, re.IGNORECASE):
        return [
            Finding(
                title="Directory listing appears enabled",
                severity="Medium",
                description="The response resembles an auto-generated directory index.",
                evidence="Response contains 'Index of /'",
                affected_url=page.url,
                owasp_category="OWASP A05:2021 - Security Misconfiguration",
                remediation="Disable directory listing in the web server and publish only intended files.",
                check_id="content.directory_listing",
            )
        ]
    return []


def check_interesting_document(page: DiscoveredURL) -> list[Finding]:
    path = urlsplit(page.url).path.lower()
    if path.endswith("/robots.txt") and page.status_code == 200:
        return [
            Finding(
                title="robots.txt available for review",
                severity="Informational",
                description="robots.txt is available and may reveal intentionally disallowed paths.",
                evidence="robots.txt returned HTTP 200",
                affected_url=page.url,
                owasp_category=None,
                remediation="Review robots.txt entries and avoid listing sensitive administrative or hidden paths.",
                check_id="content.robots",
            )
        ]
    if path.endswith("/sitemap.xml") and page.status_code == 200:
        return [
            Finding(
                title="sitemap.xml available for review",
                severity="Informational",
                description="sitemap.xml is available and may reveal crawlable application paths.",
                evidence="sitemap.xml returned HTTP 200",
                affected_url=page.url,
                owasp_category=None,
                remediation="Review sitemap entries and remove URLs that should not be public.",
                check_id="content.sitemap",
            )
        ]
    return []


def run_probe_checks(base_url: str, timeout: float = 8.0) -> list[Finding]:
    crawler = Crawler(timeout=timeout)
    findings: list[Finding] = []
    base = normalize_url(base_url)
    for path in (*SENSITIVE_FILES, "robots.txt", "sitemap.xml"):
        probe_url = base.rstrip("/") + "/" + path
        page = crawler.fetch(probe_url)
        body = getattr(page, "_body", "")
        if path in {"robots.txt", "sitemap.xml"}:
            findings.extend(check_interesting_document(page))
        elif page.status_code == 200 and body.strip():
            findings.append(
                Finding(
                    title="Potentially sensitive file exposed",
                    severity="High",
                    description="A commonly sensitive file path returned content.",
                    evidence=f"{path} returned HTTP 200",
                    affected_url=probe_url,
                    owasp_category="OWASP A05:2021 - Security Misconfiguration",
                    remediation="Remove sensitive files from the web root and block direct access at the server layer.",
                    check_id="content.sensitive_file",
                )
            )
        findings.extend(check_directory_listing(page))
    findings.extend(check_cors(base, timeout=timeout))
    findings.extend(check_reflected_xss(base, timeout=timeout))
    findings.extend(check_sql_errors(base, timeout=timeout))
    return findings


def check_cors(url: str, timeout: float = 8.0) -> list[Finding]:
    opener = build_opener()
    origin = "https://oreo.invalid"
    request = Request(url, headers={"User-Agent": "SACS-Oreo/0.1", "Origin": origin})
    try:
        with opener.open(request, timeout=timeout) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
    except OSError:
        return []

    allow_origin = headers.get("access-control-allow-origin", "")
    allow_credentials = headers.get("access-control-allow-credentials", "").lower()
    if allow_origin == "*" and allow_credentials == "true":
        severity = "High"
        evidence = "Access-Control-Allow-Origin: * with credentials enabled"
    elif allow_origin == origin:
        severity = "Medium"
        evidence = f"Origin {origin} was reflected in Access-Control-Allow-Origin"
    else:
        return []

    return [
        Finding(
            title="Potential CORS misconfiguration",
            severity=severity,
            description="The application appears to trust an arbitrary Origin value.",
            evidence=evidence,
            affected_url=url,
            owasp_category="OWASP A05:2021 - Security Misconfiguration",
            remediation="Use a strict allowlist of trusted origins and avoid wildcard origins for sensitive routes.",
            check_id="cors.origin",
        )
    ]


def _fetch_probe_body(url: str, timeout: float) -> tuple[int | None, str]:
    crawler = Crawler(timeout=timeout)
    page = crawler.fetch(url)
    return page.status_code, getattr(page, "_body", "")


def check_reflected_xss(url: str, timeout: float = 8.0) -> list[Finding]:
    probe_url = add_query_param(url, "oreo_xss", XSS_PAYLOAD)
    status, body = _fetch_probe_body(probe_url, timeout)
    if status and status < 500 and XSS_PAYLOAD in body:
        return [
            Finding(
                title="Basic reflected input detected",
                severity="Medium",
                description="A harmless marker submitted in the query string was reflected in the response body.",
                evidence=f"Reflected marker {XSS_PAYLOAD}",
                affected_url=probe_url,
                owasp_category="OWASP A03:2021 - Injection",
                remediation="Contextually encode reflected user input and validate input based on expected format.",
                check_id="xss.reflection",
            )
        ]
    return []


def check_sql_errors(url: str, timeout: float = 8.0) -> list[Finding]:
    probe_url = add_query_param(url, "oreo_sql", SQL_PROBE)
    status, body = _fetch_probe_body(probe_url, timeout)
    if status and any(re.search(pattern, body, re.IGNORECASE) for pattern in SQL_ERROR_PATTERNS):
        return [
            Finding(
                title="SQL error pattern detected",
                severity="High",
                description="A non-destructive quote probe produced a response resembling a database error.",
                evidence="Response matched a known SQL error pattern",
                affected_url=probe_url,
                owasp_category="OWASP A03:2021 - Injection",
                remediation="Use parameterized queries and suppress detailed database errors in HTTP responses.",
                check_id="sql.error_pattern",
            )
        ]
    return []


def run_passive_checks(base_url: str, pages: list[DiscoveredURL]) -> list[Finding]:
    findings = check_https(base_url)
    for page in pages:
        findings.extend(check_security_headers(page, base_url))
        findings.extend(check_cookies(page))
        findings.extend(check_directory_listing(page))
        findings.extend(check_interesting_document(page))
    return _deduplicate_findings(findings)


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    unique: dict[tuple[str, str, str], Finding] = {}
    for finding in findings:
        unique[(finding.check_id, finding.affected_url, finding.evidence)] = finding
    return list(unique.values())

