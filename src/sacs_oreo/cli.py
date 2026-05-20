from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .checks import _deduplicate_findings, run_passive_checks, run_probe_checks
from .crawler import Crawler
from .models import ScanReport
from .reporting import write_html_report, write_json_report
from .safety import DEFAULT_SCAN_MODE, SCAN_MODES, get_scan_mode
from .url_utils import normalize_url


LEGAL_WARNING = """
SACS Oreo is for authorized security assessment only.

Before continuing, confirm that you have explicit permission to scan the target.
Do not use this tool against systems you do not own or have written authorization
to test. This MVP performs safe, non-destructive checks only.
""".strip()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _confirm_authorization(non_interactive: bool) -> bool:
    print(LEGAL_WARNING)
    if non_interactive:
        return True
    answer = input("Type I HAVE AUTHORIZATION to continue: ").strip()
    return answer == "I HAVE AUTHORIZATION"


def scan(args: argparse.Namespace) -> int:
    if not _confirm_authorization(args.i_have_authorization):
        print("Authorization was not confirmed. Scan aborted.", file=sys.stderr)
        return 2

    mode = get_scan_mode(args.mode)
    target = normalize_url(args.target)
    started_at = _utc_now()
    crawler = Crawler(timeout=args.timeout)
    pages = crawler.crawl(target, max_pages=args.max_pages)
    findings = run_passive_checks(target, pages)
    if mode.runs_validation_probes:
        findings.extend(run_probe_checks(target, timeout=args.timeout))
    findings = _deduplicate_findings(findings)
    completed_at = _utc_now()

    report = ScanReport(
        tool="SACS Oreo",
        version=__version__,
        target=target,
        scan_mode=mode.name,
        started_at=started_at,
        completed_at=completed_at,
        authorization_confirmed=True,
        discovered_urls=pages,
        findings=findings,
    )

    output_dir = Path(args.output_dir)
    json_path = write_json_report(report, output_dir / "oreo-report.json")
    html_path = write_html_report(report, output_dir / "oreo-report.html")

    print(f"Scan complete: {len(pages)} URLs discovered, {len(findings)} findings.")
    print(f"Mode: {mode.name} - {mode.description}")
    print(f"JSON report: {json_path}")
    print(f"HTML report: {html_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sacs-oreo",
        description="SACS Oreo authorized web application security assessment CLI.",
    )
    parser.add_argument("--version", action="version", version=f"SACS Oreo {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run an authorized scan against a target URL.")
    scan_parser.add_argument("target", help="Base URL to scan.")
    scan_parser.add_argument(
        "--mode",
        choices=sorted(SCAN_MODES),
        default=DEFAULT_SCAN_MODE,
        help="Scan safety mode: passive skips validation probes; safe runs harmless probes; active is reserved for controlled testing.",
    )
    scan_parser.add_argument("--max-pages", type=int, default=50, help="Maximum same-host pages to crawl.")
    scan_parser.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout in seconds.")
    scan_parser.add_argument("--output-dir", default="reports", help="Directory for JSON and HTML reports.")
    scan_parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="Confirm authorization non-interactively after displaying the legal warning.",
    )
    scan_parser.set_defaults(func=scan)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
