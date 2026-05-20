from __future__ import annotations

from dataclasses import dataclass, field

from .models import EvidenceArtifact, Finding


@dataclass(frozen=True, slots=True)
class FindingTemplate:
    id: str
    title: str
    severity: str
    confidence: str
    reproducibility: str
    category: str
    owasp: str | None
    business_impact: str
    recommendation: str
    references: tuple[str, ...] = field(default_factory=tuple)


FINDING_CATALOG = {
    "headers.csp": FindingTemplate(
        id="OREO-001",
        title="Missing Content Security Policy",
        severity="Medium",
        confidence="High",
        reproducibility="Reproducible",
        category="Security Headers",
        owasp="A05:2021",
        business_impact="This can make it easier for a successful script injection issue to affect customers. For fintech, e-commerce, school portals, NGOs, clinics, and member platforms collecting personal data, fix this before public launch or major campaigns.",
        recommendation="Add a restrictive Content-Security-Policy header to reduce script injection and data exfiltration risk.",
    ),
    "headers.hsts": FindingTemplate(
        id="OREO-002",
        title="Missing Strict Transport Security",
        severity="Medium",
        confidence="High",
        reproducibility="Reproducible",
        category="Security Headers",
        owasp="A02:2021",
        business_impact="Visitors may be easier to downgrade onto an unsafe connection, especially on public Wi-Fi in offices, cafes, campuses, hotels, or shared workspaces. For payment, login, and registration portals, this can weaken customer trust.",
        recommendation="Serve the site over HTTPS and set Strict-Transport-Security with an appropriate max-age.",
    ),
    "headers.content_type_options": FindingTemplate(
        id="OREO-003",
        title="Missing X-Content-Type-Options",
        severity="Low",
        confidence="High",
        reproducibility="Reproducible",
        category="Security Headers",
        owasp="A05:2021",
        business_impact="Browsers may try to guess file types instead of trusting the server. For SMEs sharing invoices, receipts, documents, or uploaded files, this can increase the chance that unsafe content is handled in the wrong way.",
        recommendation="Set X-Content-Type-Options: nosniff to reduce MIME sniffing risk.",
    ),
    "headers.frame_options": FindingTemplate(
        id="OREO-004",
        title="Missing X-Frame-Options",
        severity="Low",
        confidence="High",
        reproducibility="Reproducible",
        category="Security Headers",
        owasp="A05:2021",
        business_impact="Attackers may be able to place your page inside another page and trick users into clicking the wrong thing. This matters for dashboards, payment flows, admin panels, and portals used by staff or customers.",
        recommendation="Set X-Frame-Options or use Content-Security-Policy frame-ancestors to control framing.",
    ),
    "headers.referrer_policy": FindingTemplate(
        id="OREO-005",
        title="Missing Referrer-Policy",
        severity="Low",
        confidence="High",
        reproducibility="Reproducible",
        category="Security Headers",
        owasp="A01:2021",
        business_impact="Links from your site may leak page addresses to other websites. If URLs contain order IDs, reset tokens, application references, student IDs, or campaign tracking data, this can expose more business context than intended.",
        recommendation="Set Referrer-Policy to limit sensitive URL leakage through referrer headers.",
    ),
    "headers.permissions_policy": FindingTemplate(
        id="OREO-006",
        title="Missing Permissions-Policy",
        severity="Informational",
        confidence="High",
        reproducibility="Reproducible",
        category="Security Headers",
        owasp="A05:2021",
        business_impact="The browser is not being told which features your site should or should not use. For customer-facing portals, it is better to explicitly limit access to features such as camera, microphone, geolocation, and payment APIs.",
        recommendation="Set Permissions-Policy to explicitly disable browser features the application does not need.",
    ),
    "cookies.secure": FindingTemplate(
        id="OREO-007",
        title="Cookie Missing Secure Attribute",
        severity="Medium",
        confidence="High",
        reproducibility="Reproducible",
        category="Cookie Security",
        owasp="A02:2021",
        business_impact="A session cookie may be sent over an unsafe connection if the user is pushed onto HTTP. For customer accounts, staff portals, wallets, learning platforms, and donation systems, this can put account access at risk.",
        recommendation="Set the Secure attribute on cookies that should only be sent over HTTPS.",
    ),
    "cookies.httponly": FindingTemplate(
        id="OREO-008",
        title="Cookie Missing HttpOnly Attribute",
        severity="Low",
        confidence="High",
        reproducibility="Reproducible",
        category="Cookie Security",
        owasp="A03:2021",
        business_impact="If a script injection issue exists elsewhere, browser scripts may be able to read this cookie. For SMEs with customer logins or admin dashboards, this can turn a smaller website bug into an account takeover risk.",
        recommendation="Set HttpOnly on session and sensitive cookies to limit script access.",
    ),
    "cookies.samesite": FindingTemplate(
        id="OREO-009",
        title="Cookie Missing SameSite Attribute",
        severity="Low",
        confidence="High",
        reproducibility="Reproducible",
        category="Cookie Security",
        owasp="A01:2021",
        business_impact="The site is not clearly limiting when browsers send cookies across sites. For portals where users submit forms, update records, make payments, or manage profiles, this can make cross-site request risks harder to control.",
        recommendation="Set SameSite=Lax or SameSite=Strict unless cross-site cookie use is explicitly required.",
    ),
    "https.plaintext": FindingTemplate(
        id="OREO-010",
        title="Target Uses HTTP",
        severity="High",
        confidence="High",
        reproducibility="Reproducible",
        category="Transport Security",
        owasp="A02:2021",
        business_impact="Customer traffic is not protected in transit. This can expose login details, forms, enquiries, payment steps, or personal data, and it can damage trust quickly for Nigerian and African SMEs trying to win online customers.",
        recommendation="Serve the application over HTTPS and redirect HTTP traffic to HTTPS.",
    ),
    "content.directory_listing": FindingTemplate(
        id="OREO-011",
        title="Directory Listing Appears Enabled",
        severity="Medium",
        confidence="Medium",
        reproducibility="Observed Once",
        category="Content Exposure",
        owasp="A05:2021",
        business_impact="Visitors may be able to browse files that were never meant to be public. This can expose backups, invoices, test files, staff documents, or old uploads, which is especially risky for small teams without a dedicated security function.",
        recommendation="Disable directory listing in the web server and publish only intended files.",
    ),
    "content.robots": FindingTemplate(
        id="OREO-012",
        title="robots.txt Available for Review",
        severity="Informational",
        confidence="High",
        reproducibility="Observed Once",
        category="Reconnaissance Information",
        owasp=None,
        business_impact="This file is normal, but it may reveal admin paths, staging areas, or sections the business would rather keep quiet. Treat it as a public signpost and make sure it does not point to sensitive areas.",
        recommendation="Review robots.txt entries and avoid listing sensitive administrative or hidden paths.",
    ),
    "content.sitemap": FindingTemplate(
        id="OREO-013",
        title="sitemap.xml Available for Review",
        severity="Informational",
        confidence="High",
        reproducibility="Observed Once",
        category="Reconnaissance Information",
        owasp=None,
        business_impact="A sitemap helps search engines, but it can also show forgotten pages, campaign pages, old portals, or draft sections. For launch readiness, confirm every listed URL is meant to be public.",
        recommendation="Review sitemap entries and remove URLs that should not be public.",
    ),
    "content.sensitive_file": FindingTemplate(
        id="OREO-014",
        title="Potentially Sensitive File Exposed",
        severity="High",
        confidence="Medium",
        reproducibility="Observed Once",
        category="Content Exposure",
        owasp="A05:2021",
        business_impact="This may expose secrets, database backups, source control details, or configuration files. For fintech, e-commerce, logistics, NGOs, and professional service firms, this can lead directly to data loss, account compromise, or reputational damage.",
        recommendation="Remove sensitive files from the web root and block direct access at the server layer.",
    ),
    "cors.origin": FindingTemplate(
        id="OREO-015",
        title="Potential CORS Misconfiguration",
        severity="Medium",
        confidence="Medium",
        reproducibility="Observed Once",
        category="CORS",
        owasp="A05:2021",
        business_impact="A poorly controlled CORS policy can let untrusted websites interact with data meant for your own app. For customer dashboards, loan portals, school systems, and internal admin tools, review this before handling real user data.",
        recommendation="Use a strict allowlist of trusted origins and avoid wildcard origins for sensitive routes.",
    ),
    "xss.reflection": FindingTemplate(
        id="OREO-016",
        title="Basic Reflected Input Detected",
        severity="Medium",
        confidence="Medium",
        reproducibility="Observed Once",
        category="Input Reflection",
        owasp="A03:2021",
        business_impact="User input is appearing back on the page. If it is not properly encoded, an attacker could imitate your login page, steal customer credentials, or weaken trust in your business. For fintech, e-commerce, school portals, and NGOs collecting personal data, fix this before public launch.",
        recommendation="Contextually encode reflected user input and validate input based on expected format.",
    ),
    "sql.error_pattern": FindingTemplate(
        id="OREO-017",
        title="SQL Error Pattern Detected",
        severity="High",
        confidence="Medium",
        reproducibility="Observed Once",
        category="Injection Signals",
        owasp="A03:2021",
        business_impact="The application is showing signs of database errors to visitors. This can expose how the backend works and may point to deeper injection risk. For businesses storing customer, student, donor, payment, or inventory records, treat this as urgent.",
        recommendation="Use parameterized queries and suppress detailed database errors in HTTP responses.",
    ),
}


def build_finding(
    key: str,
    affected_url: str,
    evidence: str,
    severity: str | None = None,
    confidence: str | None = None,
    reproducibility: str | None = None,
    evidence_artifacts: list[EvidenceArtifact] | None = None,
) -> Finding:
    template = FINDING_CATALOG[key]
    return Finding(
        id=template.id,
        title=template.title,
        severity=severity or template.severity,
        confidence=confidence or template.confidence,
        reproducibility=reproducibility or template.reproducibility,
        category=template.category,
        owasp=template.owasp,
        affected_url=affected_url,
        evidence=evidence,
        evidence_artifacts=evidence_artifacts or [],
        business_impact=template.business_impact,
        recommendation=template.recommendation,
        references=list(template.references),
    )
