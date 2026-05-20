import argparse
import tempfile
import unittest
from unittest.mock import patch

from sacs_oreo import cli
from sacs_oreo.models import DiscoveredURL, Finding
from sacs_oreo.safety import get_scan_mode


class SafetyModeTests(unittest.TestCase):
    def test_scan_mode_capabilities(self):
        self.assertFalse(get_scan_mode("passive").runs_validation_probes)
        self.assertTrue(get_scan_mode("safe").runs_validation_probes)
        self.assertTrue(get_scan_mode("active").runs_validation_probes)

    def test_parser_accepts_scan_mode(self):
        args = cli.build_parser().parse_args([
            "scan",
            "https://example.com",
            "--mode",
            "passive",
            "--i-have-authorization",
        ])

        self.assertEqual(args.mode, "passive")

    def test_passive_mode_skips_probe_checks(self):
        args = argparse.Namespace(
            target="https://example.com",
            mode="passive",
            max_pages=1,
            timeout=1.0,
            output_dir="unused",
            i_have_authorization=True,
        )
        pages = [DiscoveredURL(url="https://example.com/", status_code=200)]

        with tempfile.TemporaryDirectory() as tmp:
            args.output_dir = tmp
            with patch.object(cli.Crawler, "crawl", return_value=pages), \
                 patch.object(cli, "run_passive_checks", return_value=[]), \
                 patch.object(cli, "run_probe_checks") as probes:
                result = cli.scan(args)

        self.assertEqual(result, 0)
        probes.assert_not_called()

    def test_safe_mode_runs_probe_checks(self):
        args = argparse.Namespace(
            target="https://example.com",
            mode="safe",
            max_pages=1,
            timeout=1.0,
            output_dir="unused",
            i_have_authorization=True,
        )
        pages = [DiscoveredURL(url="https://example.com/", status_code=200)]
        finding = Finding(
            id="OREO-999",
            title="Probe finding",
            severity="Low",
            category="Test Category",
            owasp=None,
            affected_url="https://example.com/",
            evidence="evidence",
            business_impact="This can reduce customer trust for a growing SME.",
            recommendation="fix",
            references=[],
        )

        with tempfile.TemporaryDirectory() as tmp:
            args.output_dir = tmp
            with patch.object(cli.Crawler, "crawl", return_value=pages), \
                 patch.object(cli, "run_passive_checks", return_value=[]), \
                 patch.object(cli, "run_probe_checks", return_value=[finding]) as probes:
                result = cli.scan(args)

        self.assertEqual(result, 0)
        probes.assert_called_once_with("https://example.com/", timeout=1.0)


if __name__ == "__main__":
    unittest.main()
