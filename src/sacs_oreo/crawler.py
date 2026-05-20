from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, build_opener

from .models import CookieInfo, DiscoveredURL, Form, FormInput
from .url_utils import in_scope_url, normalize_url


class _PageParser(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__()
        self.page_url = page_url
        self.links: set[str] = set()
        self.forms: list[Form] = []
        self._current_form: Form | None = None
        self.technologies: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {name.lower(): value for name, value in attrs}
        if tag.lower() in {"a", "link"} and attr_map.get("href"):
            self.links.add(urljoin(self.page_url, attr_map["href"] or ""))
        elif tag.lower() in {"script", "img", "iframe"} and attr_map.get("src"):
            self.links.add(urljoin(self.page_url, attr_map["src"] or ""))
        elif tag.lower() == "form":
            self._current_form = Form(
                action=attr_map.get("action"),
                method=(attr_map.get("method") or "GET").upper(),
            )
        elif tag.lower() == "input" and self._current_form is not None:
            self._current_form.inputs.append(
                FormInput(
                    name=attr_map.get("name"),
                    input_type=attr_map.get("type"),
                    value=attr_map.get("value"),
                )
            )
        elif tag.lower() == "meta":
            name = (attr_map.get("name") or "").lower()
            content = attr_map.get("content")
            if name == "generator" and content:
                self.technologies.add(f"Generator: {content}")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def _parse_cookies(cookie_headers: Iterable[str]) -> list[CookieInfo]:
    parsed: list[CookieInfo] = []
    for header in cookie_headers:
        cookie = SimpleCookie()
        cookie.load(header)
        for morsel in cookie.values():
            attributes: dict[str, str | bool] = {}
            for key in ("secure", "httponly", "samesite", "path", "domain", "expires", "max-age"):
                value = morsel[key]
                if key in {"secure", "httponly"}:
                    attributes[key] = bool(value)
                elif value:
                    attributes[key] = value
            parsed.append(CookieInfo(name=morsel.key, value=morsel.value, attributes=attributes))
    return parsed


def _detect_technologies(headers: dict[str, str], parser_technologies: Iterable[str]) -> list[str]:
    technologies = set(parser_technologies)
    for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator", "via"):
        for key, value in headers.items():
            if key.lower() == header and value:
                technologies.add(f"{key}: {value}")
    return sorted(technologies)


class Crawler:
    def __init__(self, timeout: float = 8.0, user_agent: str = "SACS-Oreo/0.1") -> None:
        self.timeout = timeout
        self.opener = build_opener()
        self.user_agent = user_agent

    def crawl(self, base_url: str, max_pages: int = 50) -> list[DiscoveredURL]:
        normalized_base = normalize_url(base_url)
        queue: deque[str] = deque([normalized_base])
        seen: set[str] = set()
        discovered: list[DiscoveredURL] = []

        while queue and len(discovered) < max_pages:
            current = normalize_url(queue.popleft())
            if current in seen or not in_scope_url(current, normalized_base):
                continue
            seen.add(current)

            page = self.fetch(current)
            discovered.append(page)

            content_type = (page.content_type or "").lower()
            body = getattr(page, "_body", "")
            if page.status_code and page.status_code < 400 and "html" in content_type and body:
                parser = _PageParser(current)
                parser.feed(body)
                page.forms = parser.forms
                page.technologies = _detect_technologies(page.response_headers, parser.technologies)
                for link in parser.links:
                    normalized_link = normalize_url(link, current)
                    if normalized_link not in seen and in_scope_url(normalized_link, normalized_base):
                        queue.append(normalized_link)
            else:
                page.technologies = _detect_technologies(page.response_headers, [])

        return discovered

    def fetch(self, url: str) -> DiscoveredURL:
        request = Request(url, headers={"User-Agent": self.user_agent})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                headers = dict(response.headers.items())
                raw_body = response.read(1024 * 1024)
                charset = response.headers.get_content_charset() or "utf-8"
                body = raw_body.decode(charset, errors="replace")
                page = DiscoveredURL(
                    url=url,
                    status_code=response.status,
                    response_headers=headers,
                    cookies=_parse_cookies(response.headers.get_all("Set-Cookie", [])),
                    content_type=response.headers.get("Content-Type"),
                )
                setattr(page, "_body", body)
                return page
        except HTTPError as error:
            headers = dict(error.headers.items()) if error.headers else {}
            page = DiscoveredURL(
                url=url,
                status_code=error.code,
                response_headers=headers,
                cookies=_parse_cookies(error.headers.get_all("Set-Cookie", []) if error.headers else []),
                content_type=headers.get("Content-Type"),
                error=str(error),
            )
            try:
                raw_body = error.read(1024 * 1024)
                setattr(page, "_body", raw_body.decode("utf-8", errors="replace"))
            except OSError:
                pass
            return page
        except (URLError, TimeoutError, OSError) as error:
            return DiscoveredURL(url=url, status_code=None, error=str(error))
