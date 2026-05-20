from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScanMode:
    name: str
    description: str
    runs_validation_probes: bool


SCAN_MODES = {
    "passive": ScanMode(
        name="passive",
        description="Crawl and analyze observed responses without validation payloads or extra probe requests.",
        runs_validation_probes=False,
    ),
    "safe": ScanMode(
        name="safe",
        description="Run passive analysis plus harmless validation probes for common exposure and injection signals.",
        runs_validation_probes=True,
    ),
    "active": ScanMode(
        name="active",
        description="Reserved for controlled authorized testing; currently constrained to the same safe checks as safe mode.",
        runs_validation_probes=True,
    ),
}

DEFAULT_SCAN_MODE = "safe"


def get_scan_mode(mode: str) -> ScanMode:
    try:
        return SCAN_MODES[mode]
    except KeyError as error:
        supported = ", ".join(sorted(SCAN_MODES))
        raise ValueError(f"Unsupported scan mode '{mode}'. Supported modes: {supported}.") from error
