from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SEVERITIES = ("Informational", "Low", "Medium", "High", "Critical")


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


@dataclass(slots=True)
class Finding:
    title: str
    severity: str
    description: str
    evidence: str
    affected_url: str
    owasp_category: str | None
    remediation: str
    check_id: str


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
        return data
