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

        self.assertIn("Missing Content-Security-Policy header", titles)
        self.assertIn("Missing Strict-Transport-Security header", titles)
        self.assertIn("Missing X-Content-Type-Options header", titles)

    def test_hsts_not_required_for_plain_http_response(self):
        page = DiscoveredURL(url="http://example.com/", status_code=200, response_headers={})

        titles = {finding.title for finding in check_security_headers(page)}

        self.assertNotIn("Missing Strict-Transport-Security header", titles)


class CookieCheckTests(unittest.TestCase):
    def test_insecure_cookie_attributes_are_reported(self):
        page = DiscoveredURL(
            url="https://example.com/",
            status_code=200,
            cookies=[CookieInfo(name="session", value="abc", attributes={})],
        )

        check_ids = {finding.check_id for finding in check_cookies(page)}

        self.assertEqual(check_ids, {"cookies.secure", "cookies.httponly", "cookies.samesite"})

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


if __name__ == "__main__":
    unittest.main()

