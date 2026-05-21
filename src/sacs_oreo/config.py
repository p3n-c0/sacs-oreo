from __future__ import annotations

import json

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10 in CI
    import tomli as tomllib

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .safety import DEFAULT_SCAN_MODE, SCAN_MODES


@dataclass(frozen=True, slots=True)
class ScanProfile:
    name: str
    mode: str
    max_pages: int
    timeout: float
    crawl_delay: float
    requests_per_second: float | None


SCAN_PROFILES = {
    "quick": ScanProfile(
        name="quick",
        mode="passive",
        max_pages=15,
        timeout=5.0,
        crawl_delay=0.0,
        requests_per_second=2.0,
    ),
    "standard": ScanProfile(
        name="standard",
        mode=DEFAULT_SCAN_MODE,
        max_pages=50,
        timeout=8.0,
        crawl_delay=0.0,
        requests_per_second=1.0,
    ),
    "deep-safe": ScanProfile(
        name="deep-safe",
        mode="safe",
        max_pages=150,
        timeout=12.0,
        crawl_delay=0.25,
        requests_per_second=0.5,
    ),
}


@dataclass(slots=True)
class ScanConfig:
    target: str | None = None
    mode: str | None = None
    profile: str = "standard"
    max_pages: int | None = None
    timeout: float | None = None
    output_dir: str | None = None
    crawl_delay: float | None = None
    requests_per_second: float | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None


@dataclass(frozen=True, slots=True)
class EffectiveScanConfig:
    target: str
    mode: str
    profile: str
    max_pages: int
    timeout: float
    output_dir: str
    crawl_delay: float
    requests_per_second: float | None
    headers: dict[str, str]
    cookies: dict[str, str]
    proxy: str | None


def load_scan_config(path: str | Path | None) -> ScanConfig:
    if path is None:
        return ScanConfig()

    config_path = Path(path)
    raw = config_path.read_text(encoding="utf-8")
    suffix = config_path.suffix.lower()
    if suffix == ".toml":
        data = tomllib.loads(raw)
    elif suffix in {".json", ".yaml", ".yml"}:
        if suffix in {".yaml", ".yml"}:
            raise ValueError("YAML config support is planned, but this build currently supports TOML and JSON config files.")
        data = json.loads(raw)
    else:
        raise ValueError("Unsupported config file type. Use .toml or .json for now.")

    scan_data = data.get("scan", data)
    if not isinstance(scan_data, dict):
        raise ValueError("Scan config must be an object or contain a [scan] object.")

    return ScanConfig(
        target=_optional_str(scan_data.get("target")),
        mode=_optional_str(scan_data.get("mode")),
        profile=_optional_str(scan_data.get("profile")) or "standard",
        max_pages=_optional_int(scan_data.get("max_pages")),
        timeout=_optional_float(scan_data.get("timeout")),
        output_dir=_optional_str(scan_data.get("output_dir")),
        crawl_delay=_optional_float(scan_data.get("crawl_delay")),
        requests_per_second=_optional_float(scan_data.get("requests_per_second")),
        headers=_string_map(scan_data.get("headers", {}), "headers"),
        cookies=_string_map(scan_data.get("cookies", {}), "cookies"),
        proxy=_optional_str(scan_data.get("proxy")),
    )


def resolve_scan_config(args: Any) -> EffectiveScanConfig:
    file_config = load_scan_config(getattr(args, "config", None))
    profile_name = getattr(args, "profile", None) or file_config.profile or "standard"
    profile = _get_profile(profile_name)

    target = getattr(args, "target", None) or file_config.target
    if not target:
        raise ValueError("A target URL is required, either as an argument or in the config file.")

    mode = getattr(args, "mode", None) or file_config.mode or profile.mode
    if mode not in SCAN_MODES:
        supported = ", ".join(sorted(SCAN_MODES))
        raise ValueError(f"Unsupported scan mode '{mode}'. Supported modes: {supported}.")

    return EffectiveScanConfig(
        target=target,
        mode=mode,
        profile=profile.name,
        max_pages=getattr(args, "max_pages", None) or file_config.max_pages or profile.max_pages,
        timeout=getattr(args, "timeout", None) or file_config.timeout or profile.timeout,
        output_dir=getattr(args, "output_dir", None) or file_config.output_dir or "reports",
        crawl_delay=getattr(args, "crawl_delay", None) if getattr(args, "crawl_delay", None) is not None else (file_config.crawl_delay if file_config.crawl_delay is not None else profile.crawl_delay),
        requests_per_second=getattr(args, "requests_per_second", None) if getattr(args, "requests_per_second", None) is not None else (file_config.requests_per_second if file_config.requests_per_second is not None else profile.requests_per_second),
        headers={**file_config.headers, **_parse_key_value_pairs(getattr(args, "header", None) or [], "header")},
        cookies={**file_config.cookies, **_parse_key_value_pairs(getattr(args, "cookie", None) or [], "cookie")},
        proxy=getattr(args, "proxy", None) or file_config.proxy,
    )


def _get_profile(name: str) -> ScanProfile:
    try:
        return SCAN_PROFILES[name]
    except KeyError as error:
        supported = ", ".join(sorted(SCAN_PROFILES))
        raise ValueError(f"Unsupported scan profile '{name}'. Supported profiles: {supported}.") from error


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    return float(value)


def _string_map(value: Any, field_name: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"Config field '{field_name}' must be a key/value object.")
    return {str(key): str(item) for key, item in value.items()}


def _parse_key_value_pairs(values: list[str], label: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for value in values:
        if ":" in value:
            key, item = value.split(":", 1)
        elif "=" in value:
            key, item = value.split("=", 1)
        else:
            raise ValueError(f"Invalid {label} value '{value}'. Use Name: Value or name=value.")
        key = key.strip()
        if not key:
            raise ValueError(f"Invalid {label} value '{value}'. Name cannot be empty.")
        parsed[key] = item.strip()
    return parsed
