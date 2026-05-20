import unittest

from sacs_oreo.findings import FINDING_CATALOG, build_finding


class FindingCatalogTests(unittest.TestCase):
    def test_catalog_ids_are_unique_and_stable(self):
        ids = [template.id for template in FINDING_CATALOG.values()]

        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(finding_id.startswith("OREO-") for finding_id in ids))

    def test_build_finding_uses_structured_schema(self):
        finding = build_finding(
            "headers.csp",
            affected_url="https://example.com/",
            evidence="content-security-policy absent from response headers",
        )

        self.assertEqual(finding.id, "OREO-001")
        self.assertEqual(finding.category, "Security Headers")
        self.assertEqual(finding.owasp, "A05:2021")
        self.assertEqual(finding.affected_url, "https://example.com/")
        self.assertEqual(finding.references, [])
        self.assertIn("Content-Security-Policy", finding.recommendation)


if __name__ == "__main__":
    unittest.main()
