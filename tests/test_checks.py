import unittest

from sacs_oreo.checks import check_cookies, check_security_headers
from sacs_oreo.models import CookieInfo, DiscoveredURL


class HeaderCheckTests(unittest.TestCase):
    def test_missing_security_headers_are_reported(self):
        page = DiscoveredURL(
            url="https://example.com/",
            status_code=200,
            response_headers={"Content-Type": "text/html"},
        )

        titles = {finding.title for finding in check_security_headers(page)}
        ids = {finding.id for finding in check_security_headers(page)}

        self.assertIn("Missing Content Security Policy", titles)
        self.assertIn("Missing Strict Transport Security", titles)
        self.assertIn("Missing X-Content-Type-Options", titles)
        self.assertIn("OREO-001", ids)

    def test_hsts_not_required_for_plain_http_response(self):
        page = DiscoveredURL(url="http://example.com/", status_code=200, response_headers={})

        titles = {finding.title for finding in check_security_headers(page)}

        self.assertNotIn("Missing Strict Transport Security", titles)


class CookieCheckTests(unittest.TestCase):
    def test_insecure_cookie_attributes_are_reported(self):
        page = DiscoveredURL(
            url="https://example.com/",
            status_code=200,
            cookies=[CookieInfo(name="session", value="abc", attributes={})],
        )

        finding_ids = {finding.id for finding in check_cookies(page)}

        self.assertEqual(finding_ids, {"OREO-007", "OREO-008", "OREO-009"})

    def test_secure_cookie_is_not_flagged_for_secure_attribute(self):
        page = DiscoveredURL(
            url="https://example.com/",
            status_code=200,
            cookies=[
                CookieInfo(
                    name="session",
                    value="abc",
                    attributes={"secure": True, "httponly": True, "samesite": "Lax"},
                )
            ],
        )

        self.assertEqual(check_cookies(page), [])

    def test_cors_probe_ignores_unexpected_transport_errors(self):
        from sacs_oreo.checks import check_cors
        from sacs_oreo.crawler import Crawler

        class BrokenOpener:
            def open(self, request, timeout):
                raise RuntimeError("simulated CORS transport failure")

        crawler = Crawler()
        crawler.opener = BrokenOpener()

        self.assertEqual(check_cors("https://example.com/", crawler), [])


if __name__ == "__main__":
    unittest.main()
