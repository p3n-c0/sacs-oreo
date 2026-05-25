import json
import tempfile
import unittest
from pathlib import Path

from sacs_oreo.models import CookieInfo, DiscoveredURL, EvidenceArtifact, Finding, ScanReport
from sacs_oreo.reporting import write_html_report, write_json_report


class ReportingTests(unittest.TestCase):
    def test_report_generation_writes_json_and_html(self):
        report = ScanReport(
            tool="SACS Oreo",
            version="0.1.0",
            target="https://example.com/",
            scan_mode="safe",
            started_at="2026-05-20T00:00:00+00:00",
            completed_at="2026-05-20T00:00:01+00:00",
            authorization_confirmed=True,
            discovered_urls=[
                DiscoveredURL(
                    url="https://example.com/",
                    status_code=200,
                    response_headers={"Set-Cookie": "session=secret", "Server": "Example"},
                    cookies=[CookieInfo(name="session", value="secret", attributes={"httponly": True})],
                    response_body_sample_bytes=128,
                    response_body_sample_sha256="abc123body",
                )
            ],
            findings=[
                Finding(
                    id="OREO-999",
                    title="Test finding",
                    severity="Low",
                    confidence="High",
                    reproducibility="Reproducible",
                    category="Test Category",
                    owasp="A05:2021",
                    affected_url="https://example.com/",
                    evidence="evidence",
                    evidence_artifacts=[
                        EvidenceArtifact(
                            kind="response-header",
                            description="Captured response headers for the affected URL.",
                            path="evidence/OREO-999-response.txt",
                            sha256="abc123",
                        )
                    ],
                    business_impact="This can reduce customer trust for a growing SME.",
                    recommendation="fix",
                    references=[],
                )
            ],
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            json_path = write_json_report(report, tmp_path / "report.json")
            html_path = write_html_report(report, tmp_path / "report.html")

            parsed = json.loads(json_path.read_text(encoding="utf-8"))
            html = html_path.read_text(encoding="utf-8")

        finding = parsed["findings"][0]
        self.assertEqual(parsed["tool"], "SACS Oreo")
        self.assertEqual(parsed["scan_mode"], "safe")
        page = parsed["discovered_urls"][0]
        self.assertEqual(page["response_headers"]["Set-Cookie"], "[redacted]")
        self.assertEqual(page["response_headers"]["Server"], "Example")
        self.assertEqual(page["cookies"][0]["value"], "[redacted]")
        self.assertEqual(page["response_body_sample_bytes"], 128)
        self.assertEqual(page["response_body_sample_sha256"], "abc123body")
        self.assertEqual(finding["id"], "OREO-999")
        self.assertEqual(finding["category"], "Test Category")
        self.assertEqual(finding["owasp"], "A05:2021")
        self.assertEqual(finding["confidence"], "High")
        self.assertEqual(finding["reproducibility"], "Reproducible")
        self.assertEqual(finding["evidence_artifacts"][0]["path"], "evidence/OREO-999-response.txt")
        self.assertEqual(finding["business_impact"], "This can reduce customer trust for a growing SME.")
        self.assertEqual(finding["recommendation"], "fix")
        self.assertEqual(finding["references"], [])
        self.assertIn("Scan mode:", html)
        self.assertIn("OREO-999", html)
        self.assertIn("Test finding", html)
        self.assertIn("Confidence", html)
        self.assertIn("Reproducibility", html)
        self.assertIn("Business Impact", html)
        self.assertIn("Recommendation", html)
        self.assertIn("https://example.com/", html)
        self.assertIn("Body Sample SHA-256", html)
        self.assertIn("abc123body", html)


if __name__ == "__main__":
    unittest.main()
