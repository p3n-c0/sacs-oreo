import hashlib
import unittest

from sacs_oreo.crawler import Crawler, _PageParser
from sacs_oreo.url_utils import in_scope_url


class CrawlerScopingTests(unittest.TestCase):
    def test_parser_discovers_links_and_forms(self):
        parser = _PageParser("https://example.com/")
        parser.feed(
            """
            <html><head><meta name="generator" content="TestCMS"></head>
            <body>
              <a href="/inside">inside</a>
              <a href="https://other.test/outside">outside</a>
              <form action="/search" method="post"><input name="q" type="text"></form>
            </body></html>
            """
        )

        scoped = [url for url in parser.links if in_scope_url(url, "https://example.com/")]
        self.assertEqual(scoped, ["https://example.com/inside"])
        self.assertEqual(len(parser.forms), 1)
        self.assertEqual(parser.forms[0].method, "POST")
        self.assertIn("Generator: TestCMS", parser.technologies)


class CrawlerTransportTests(unittest.TestCase):
    def test_request_headers_include_custom_headers_and_cookies(self):
        crawler = Crawler(
            headers={"X-Test": "yes", "User-Agent": "Custom-UA"},
            cookies={"session": "abc", "theme": "dark"},
        )

        headers = crawler._request_headers()

        self.assertEqual(headers["User-Agent"], "Custom-UA")
        self.assertEqual(headers["X-Test"], "yes")
        self.assertEqual(headers["Cookie"], "session=abc; theme=dark")

    def test_explicit_cookie_header_is_not_overwritten(self):
        crawler = Crawler(headers={"Cookie": "manual=yes"}, cookies={"session": "abc"})

        self.assertEqual(crawler._request_headers()["Cookie"], "manual=yes")

    def test_proxy_builds_proxy_handler(self):
        crawler = Crawler(proxy="http://127.0.0.1:8080")

        self.assertEqual(crawler.proxy, "http://127.0.0.1:8080")

    def test_throttle_uses_largest_delay(self):
        sleeps = []
        now = [10.0]
        crawler = Crawler(
            crawl_delay=0.25,
            requests_per_second=2.0,
            sleeper=sleeps.append,
            monotonic=lambda: now[0],
        )
        crawler._last_request_at = 9.75

        crawler._throttle()

        self.assertEqual(sleeps, [0.25])

    def test_throttle_does_not_sleep_before_first_request(self):
        sleeps = []
        crawler = Crawler(crawl_delay=1.0, sleeper=sleeps.append)

        crawler._throttle()

        self.assertEqual(sleeps, [])

    def test_fetch_records_safe_response_evidence_summary(self):
        body = b"<html><body>ok</body></html>"

        class Headers:
            def items(self):
                return [("Content-Type", "text/html"), ("Set-Cookie", "session=secret; HttpOnly")]

            def get_content_charset(self):
                return "utf-8"

            def get(self, name):
                if name.lower() == "content-type":
                    return "text/html"
                return None

            def get_all(self, name, default=None):
                if name.lower() == "set-cookie":
                    return ["session=secret; HttpOnly"]
                return default or []

        class Response:
            status = 200
            headers = Headers()

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self, limit):
                return body

        class Opener:
            def open(self, request, timeout):
                return Response()

        crawler = Crawler()
        crawler.opener = Opener()

        page = crawler.fetch("https://example.com/")

        self.assertEqual(page.response_body_sample_bytes, len(body))
        self.assertEqual(page.response_body_sample_sha256, hashlib.sha256(body).hexdigest())
        self.assertEqual(page.request_method, "GET")
        self.assertEqual(page.cookies[0].name, "session")


if __name__ == "__main__":
    unittest.main()
