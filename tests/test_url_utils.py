import unittest

from sacs_oreo.url_utils import in_scope_url, normalize_url, same_host


class URLUtilsTests(unittest.TestCase):
    def test_normalize_adds_scheme_and_removes_fragment(self):
        self.assertEqual(normalize_url("Example.COM:443/a?b=2&a=1#frag"), "https://example.com/a?a=1&b=2")

    def test_relative_url_uses_base(self):
        self.assertEqual(normalize_url("../login", "https://example.com/app/page"), "https://example.com/login")

    def test_same_host_blocks_other_domains(self):
        self.assertTrue(same_host("https://example.com/a", "https://example.com"))
        self.assertFalse(same_host("https://evil.example/a", "https://example.com"))

    def test_in_scope_only_http_https_same_host(self):
        self.assertTrue(in_scope_url("/admin", "https://example.com"))
        self.assertFalse(in_scope_url("mailto:admin@example.com", "https://example.com"))
        self.assertFalse(in_scope_url("https://other.example.com", "https://example.com"))


if __name__ == "__main__":
    unittest.main()

