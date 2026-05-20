from __future__ import annotations

import re
from urllib.parse import urlsplit
from urllib.request import Request, build_opener

from .crawler import Crawler
from .findings import build_finding
from .models import DiscoveredURL, Finding
from .url_utils import add_query_param, normalize_url


SECURITY_HEADERS = {
    "content-security-policy": "headers.csp",
    "strict-transport-security": "headers.hsts",
    "x-content-type-options": "headers.content_type_options",
    "x-frame-options": "headers.frame_options",
    "referrer-policy": "headers.referrer_policy",
    "permissions-policy": "headers.permissions_policy",
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
    for header, finding_key in SECURITY_HEADERS.items():
        if header == "strict-transport-security" and urlsplit(page.url).scheme != "https":
            continue
        if header not in present:
            findings.append(
                build_finding(
                    finding_key,
                    affected_url=page.url,
                    evidence=f"{header} absent from response headers",
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
                build_finding("cookies.secure", page.url, f"Cookie {cookie.name} lacks Secure")
            )
        if not attrs.get("httponly"):
            findings.append(
                build_finding("cookies.httponly", page.url, f"Cookie {cookie.name} lacks HttpOnly")
            )
        if not attrs.get("samesite"):
            findings.append(
                build_finding("cookies.samesite", page.url, f"Cookie {cookie.name} lacks SameSite")
            )
    return findings


def check_https(base_url: str) -> list[Finding]:
    normalized = normalize_url(base_url)
    if urlsplit(normalized).scheme == "http":
        return [build_finding("https.plaintext", normalized, normalized)]
    return []


def check_directory_listing(page: DiscoveredURL) -> list[Finding]:
    body = getattr(page, "_body", "")
    if page.status_code == 200 and re.search(r"<title>Index of /|Index of /", body, re.IGNORECASE):
        return [build_finding("content.directory_listing", page.url, "Response contains 'Index of /'")]
    return []


def check_interesting_document(page: DiscoveredURL) -> list[Finding]:
    path = urlsplit(page.url).path.lower()
    if path.endswith("/robots.txt") and page.status_code == 200:
        return [build_finding("content.robots", page.url, "robots.txt returned HTTP 200")]
    if path.endswith("/sitemap.xml") and page.status_code == 200:
        return [build_finding("content.sitemap", page.url, "sitemap.xml returned HTTP 200")]
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
                build_finding("content.sensitive_file", probe_url, f"{path} returned HTTP 200")
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

    return [build_finding("cors.origin", url, evidence, severity=severity)]


def _fetch_probe_body(url: str, timeout: float) -> tuple[int | None, str]:
    crawler = Crawler(timeout=timeout)
    page = crawler.fetch(url)
    return page.status_code, getattr(page, "_body", "")


def check_reflected_xss(url: str, timeout: float = 8.0) -> list[Finding]:
    probe_url = add_query_param(url, "oreo_xss", XSS_PAYLOAD)
    status, body = _fetch_probe_body(probe_url, timeout)
    if status and status < 500 and XSS_PAYLOAD in body:
        return [build_finding("xss.reflection", probe_url, f"Reflected marker {XSS_PAYLOAD}")]
    return []


def check_sql_errors(url: str, timeout: float = 8.0) -> list[Finding]:
    probe_url = add_query_param(url, "oreo_sql", SQL_PROBE)
    status, body = _fetch_probe_body(probe_url, timeout)
    if status and any(re.search(pattern, body, re.IGNORECASE) for pattern in SQL_ERROR_PATTERNS):
        return [build_finding("sql.error_pattern", probe_url, "Response matched a known SQL error pattern")]
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
        unique[(finding.id, finding.affected_url, finding.evidence)] = finding
    return list(unique.values())
