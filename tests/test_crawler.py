import unittest

from sacs_oreo.crawler import _PageParser
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


if __name__ == "__main__":
    unittest.main()

