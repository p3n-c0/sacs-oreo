from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding


@dataclass(frozen=True, slots=True)
class FindingTemplate:
    id: str
    title: str
    severity: str
    category: str
    owasp: str | None
    recommendation: str
    references: tuple[str, ...] = field(default_factory=tuple)


FINDING_CATALOG = {
    "headers.csp": FindingTemplate(
        id="OREO-001",
        title="Missing Content Security Policy",
        severity="Medium",
        category="Security Headers",
        owasp="A05:2021",
        recommendation="Add a restrictive Content-Security-Policy header to reduce script injection and data exfiltration risk.",
    ),
    "headers.hsts": FindingTemplate(
        id="OREO-002",
        title="Missing Strict Transport Security",
        severity="Medium",
        category="Security Headers",
        owasp="A02:2021",
        recommendation="Serve the site over HTTPS and set Strict-Transport-Security with an appropriate max-age.",
    ),
    "headers.content_type_options": FindingTemplate(
        id="OREO-003",
        title="Missing X-Content-Type-Options",
        severity="Low",
        category="Security Headers",
        owasp="A05:2021",
        recommendation="Set X-Content-Type-Options: nosniff to reduce MIME sniffing risk.",
    ),
    "headers.frame_options": FindingTemplate(
        id="OREO-004",
        title="Missing X-Frame-Options",
        severity="Low",
        category="Security Headers",
        owasp="A05:2021",
        recommendation="Set X-Frame-Options or use Content-Security-Policy frame-ancestors to control framing.",
    ),
    "headers.referrer_policy": FindingTemplate(
        id="OREO-005",
        title="Missing Referrer-Policy",
        severity="Low",
        category="Security Headers",
        owasp="A01:2021",
        recommendation="Set Referrer-Policy to limit sensitive URL leakage through referrer headers.",
    ),
    "headers.permissions_policy": FindingTemplate(
        id="OREO-006",
        title="Missing Permissions-Policy",
        severity="Informational",
        category="Security Headers",
        owasp="A05:2021",
        recommendation="Set Permissions-Policy to explicitly disable browser features the application does not need.",
    ),
    "cookies.secure": FindingTemplate(
        id="OREO-007",
        title="Cookie Missing Secure Attribute",
        severity="Medium",
        category="Cookie Security",
        owasp="A02:2021",
        recommendation="Set the Secure attribute on cookies that should only be sent over HTTPS.",
    ),
    "cookies.httponly": FindingTemplate(
        id="OREO-008",
        title="Cookie Missing HttpOnly Attribute",
        severity="Low",
        category="Cookie Security",
        owasp="A03:2021",
        recommendation="Set HttpOnly on session and sensitive cookies to limit script access.",
    ),
    "cookies.samesite": FindingTemplate(
        id="OREO-009",
        title="Cookie Missing SameSite Attribute",
        severity="Low",
        category="Cookie Security",
        owasp="A01:2021",
        recommendation="Set SameSite=Lax or SameSite=Strict unless cross-site cookie use is explicitly required.",
    ),
    "https.plaintext": FindingTemplate(
        id="OREO-010",
        title="Target Uses HTTP",
        severity="High",
        category="Transport Security",
        owasp="A02:2021",
        recommendation="Serve the application over HTTPS and redirect HTTP traffic to HTTPS.",
    ),
    "content.directory_listing": FindingTemplate(
        id="OREO-011",
        title="Directory Listing Appears Enabled",
        severity="Medium",
        category="Content Exposure",
        owasp="A05:2021",
        recommendation="Disable directory listing in the web server and publish only intended files.",
    ),
    "content.robots": FindingTemplate(
        id="OREO-012",
        title="robots.txt Available for Review",
        severity="Informational",
        category="Reconnaissance Information",
        owasp=None,
        recommendation="Review robots.txt entries and avoid listing sensitive administrative or hidden paths.",
    ),
    "content.sitemap": FindingTemplate(
        id="OREO-013",
        title="sitemap.xml Available for Review",
        severity="Informational",
        category="Reconnaissance Information",
        owasp=None,
        recommendation="Review sitemap entries and remove URLs that should not be public.",
    ),
    "content.sensitive_file": FindingTemplate(
        id="OREO-014",
        title="Potentially Sensitive File Exposed",
        severity="High",
        category="Content Exposure",
        owasp="A05:2021",
        recommendation="Remove sensitive files from the web root and block direct access at the server layer.",
    ),
    "cors.origin": FindingTemplate(
        id="OREO-015",
        title="Potential CORS Misconfiguration",
        severity="Medium",
        category="CORS",
        owasp="A05:2021",
        recommendation="Use a strict allowlist of trusted origins and avoid wildcard origins for sensitive routes.",
    ),
    "xss.reflection": FindingTemplate(
        id="OREO-016",
        title="Basic Reflected Input Detected",
        severity="Medium",
        category="Input Reflection",
        owasp="A03:2021",
        recommendation="Contextually encode reflected user input and validate input based on expected format.",
    ),
    "sql.error_pattern": FindingTemplate(
        id="OREO-017",
        title="SQL Error Pattern Detected",
        severity="High",
        category="Injection Signals",
        owasp="A03:2021",
        recommendation="Use parameterized queries and suppress detailed database errors in HTTP responses.",
    ),
}


def build_finding(key: str, affected_url: str, evidence: str, severity: str | None = None) -> Finding:
    template = FINDING_CATALOG[key]
    return Finding(
        id=template.id,
        title=template.title,
        severity=severity or template.severity,
        category=template.category,
        owasp=template.owasp,
        affected_url=affected_url,
        evidence=evidence,
        recommendation=template.recommendation,
        references=list(template.references),
    )
