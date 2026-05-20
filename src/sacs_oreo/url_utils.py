from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit


def normalize_url(url: str, base_url: str | None = None) -> str:
    """Return a stable URL for crawling and report de-duplication."""
    candidate = url.strip()
    if base_url:
        candidate = urljoin(base_url, candidate)
    elif "://" not in candidate:
        candidate = "https://" + candidate

    split = urlsplit(candidate)
    scheme = (split.scheme or "https").lower()
    hostname = (split.hostname or "").lower()
    port = split.port

    netloc = hostname
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{hostname}:{port}"

    path = split.path or "/"
    query = urlencode(sorted(parse_qsl(split.query, keep_blank_values=True)), doseq=True)
    return urlunsplit((scheme, netloc, path, query, ""))


def same_host(url: str, base_url: str) -> bool:
    return urlsplit(normalize_url(url)).hostname == urlsplit(normalize_url(base_url)).hostname


def in_scope_url(url: str, base_url: str) -> bool:
    split = urlsplit(normalize_url(url, base_url))
    base_split = urlsplit(normalize_url(base_url))
    return split.scheme in {"http", "https"} and split.hostname == base_split.hostname


def add_query_param(url: str, key: str, value: str) -> str:
    split = urlsplit(url)
    params = parse_qsl(split.query, keep_blank_values=True)
    params.append((key, value))
    return urlunsplit((split.scheme, split.netloc, split.path or "/", urlencode(params), ""))
