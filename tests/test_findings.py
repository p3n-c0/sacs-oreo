import unittest

from sacs_oreo.findings import FINDING_CATALOG, build_finding
from sacs_oreo.models import CONFIDENCE_LEVELS, REPRODUCIBILITY_LEVELS


class FindingCatalogTests(unittest.TestCase):
    def test_catalog_ids_are_unique_and_stable(self):
        ids = [template.id for template in FINDING_CATALOG.values()]

        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(finding_id.startswith("OREO-") for finding_id in ids))

    def test_catalog_templates_include_confidence_and_reproducibility(self):
        for template in FINDING_CATALOG.values():
            self.assertIn(template.confidence, CONFIDENCE_LEVELS)
            self.assertIn(template.reproducibility, REPRODUCIBILITY_LEVELS)

    def test_catalog_templates_include_business_impact(self):
        for template in FINDING_CATALOG.values():
            self.assertTrue(template.business_impact.strip())
            self.assertGreater(len(template.business_impact), 40)

    def test_build_finding_uses_structured_schema(self):
        finding = build_finding(
            "headers.csp",
            affected_url="https://example.com/",
            evidence="content-security-policy absent from response headers",
        )

        self.assertEqual(finding.id, "OREO-001")
        self.assertEqual(finding.category, "Security Headers")
        self.assertEqual(finding.owasp, "A05:2021")
        self.assertEqual(finding.confidence, "High")
        self.assertEqual(finding.reproducibility, "Reproducible")
        self.assertEqual(finding.affected_url, "https://example.com/")
        self.assertEqual(finding.evidence_artifacts, [])
        self.assertEqual(finding.references, [])
        self.assertIn("Content-Security-Policy", finding.recommendation)
        self.assertIn("fintech", finding.business_impact.lower())


if __name__ == "__main__":
    unittest.main()
