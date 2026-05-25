from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SEVERITIES = ("Informational", "Low", "Medium", "High", "Critical")
CONFIDENCE_LEVELS = ("Low", "Medium", "High")
REPRODUCIBILITY_LEVELS = ("Unconfirmed", "Observed Once", "Reproducible")
SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
}
REDACTED_VALUE = "[redacted]"


@dataclass(slots=True)
class FormInput:
    name: str | None
    input_type: str | None
    value: str | None


@dataclass(slots=True)
class Form:
    action: str | None
    method: str
    inputs: list[FormInput] = field(default_factory=list)


@dataclass(slots=True)
class CookieInfo:
    name: str
    value: str
    attributes: dict[str, str | bool] = field(default_factory=dict)


@dataclass(slots=True)
class EvidenceArtifact:
    kind: str
    description: str
    path: str | None = None
    sha256: str | None = None


@dataclass
class DiscoveredURL:
    url: str
    status_code: int | None
    response_headers: dict[str, str] = field(default_factory=dict)
    cookies: list[CookieInfo] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    content_type: str | None = None
    error: str | None = None
    request_method: str = "GET"
    response_body_sample_bytes: int | None = None
    response_body_sample_sha256: str | None = None


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: str
    confidence: str
    reproducibility: str
    category: str
    owasp: str | None
    affected_url: str
    evidence: str
    evidence_artifacts: list[EvidenceArtifact]
    business_impact: str
    recommendation: str
    references: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanReport:
    tool: str
    version: str
    target: str
    scan_mode: str
    started_at: str
    completed_at: str
    authorization_confirmed: bool
    discovered_urls: list[DiscoveredURL]
    findings: list[Finding]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for page in data["discovered_urls"]:
            page.pop("_body", None)
            page["response_headers"] = _redact_headers(page.get("response_headers", {}))
            for cookie in page.get("cookies", []):
                cookie["value"] = REDACTED_VALUE
        return data


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in SENSITIVE_HEADER_NAMES:
            redacted[name] = REDACTED_VALUE
        else:
            redacted[name] = value
    return redacted
