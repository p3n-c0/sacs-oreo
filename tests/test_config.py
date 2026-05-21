import argparse
import tempfile
import unittest
from pathlib import Path

from sacs_oreo.config import SCAN_PROFILES, load_scan_config, resolve_scan_config


def _scan_args(**overrides):
    values = {
        "target": "https://example.com",
        "config": None,
        "profile": None,
        "mode": None,
        "max_pages": None,
        "timeout": None,
        "output_dir": None,
        "crawl_delay": None,
        "requests_per_second": None,
        "header": [],
        "cookie": [],
        "proxy": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class ScanConfigTests(unittest.TestCase):
    def test_load_toml_scan_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oreo.toml"
            path.write_text(
                """
[scan]
target = "https://example.com"
profile = "deep-safe"
mode = "safe"
max_pages = 25
timeout = 9
output_dir = "reports/example"
crawl_delay = 0.5
requests_per_second = 1.5
proxy = "http://127.0.0.1:8080"

[scan.headers]
User-Agent = "SACS-Oreo-Test"
X-Test = "yes"

[scan.cookies]
session = "abc"
""".strip(),
                encoding="utf-8",
            )

            config = load_scan_config(path)

        self.assertEqual(config.target, "https://example.com")
        self.assertEqual(config.profile, "deep-safe")
        self.assertEqual(config.max_pages, 25)
        self.assertEqual(config.timeout, 9.0)
        self.assertEqual(config.headers["User-Agent"], "SACS-Oreo-Test")
        self.assertEqual(config.cookies["session"], "abc")
        self.assertEqual(config.proxy, "http://127.0.0.1:8080")

    def test_resolve_config_uses_profile_defaults(self):
        args = argparse.Namespace(
            target="https://example.com",
            config=None,
            profile="quick",
            mode=None,
            max_pages=None,
            timeout=None,
            output_dir=None,
            crawl_delay=None,
            requests_per_second=None,
            header=[],
            cookie=[],
            proxy=None,
        )

        config = resolve_scan_config(args)

        self.assertEqual(config.profile, "quick")
        self.assertEqual(config.mode, SCAN_PROFILES["quick"].mode)
        self.assertEqual(config.max_pages, SCAN_PROFILES["quick"].max_pages)
        self.assertEqual(config.timeout, SCAN_PROFILES["quick"].timeout)

    def test_cli_overrides_file_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oreo.toml"
            path.write_text(
                """
[scan]
target = "https://config.example"
profile = "standard"
max_pages = 20

[scan.headers]
X-Config = "yes"
""".strip(),
                encoding="utf-8",
            )
            args = argparse.Namespace(
                target="https://cli.example",
                config=str(path),
                profile="deep-safe",
                mode="passive",
                max_pages=5,
                timeout=None,
                output_dir="reports/cli",
                crawl_delay=None,
                requests_per_second=None,
                header=["X-CLI: yes"],
                cookie=["session=abc"],
                proxy=None,
            )

            config = resolve_scan_config(args)

        self.assertEqual(config.target, "https://cli.example")
        self.assertEqual(config.profile, "deep-safe")
        self.assertEqual(config.mode, "passive")
        self.assertEqual(config.max_pages, 5)
        self.assertEqual(config.output_dir, "reports/cli")
        self.assertEqual(config.headers["X-Config"], "yes")
        self.assertEqual(config.headers["X-CLI"], "yes")
        self.assertEqual(config.cookies["session"], "abc")

    def test_missing_target_is_config_error(self):
        args = argparse.Namespace(
            target=None,
            config=None,
            profile=None,
            mode=None,
            max_pages=None,
            timeout=None,
            output_dir=None,
            crawl_delay=None,
            requests_per_second=None,
            header=[],
            cookie=[],
            proxy=None,
        )

        with self.assertRaisesRegex(ValueError, "target URL is required"):
            resolve_scan_config(args)

    def test_load_yaml_scan_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oreo.yaml"
            path.write_text(
                """
scan:
  target: https://example.com
  profile: quick
  mode: passive
  max_pages: 12
  timeout: 4
  output_dir: reports/yaml
  crawl_delay: 0.2
  requests_per_second: 0.5
  headers:
    User-Agent: SACS-Oreo-YAML-Test
  cookies:
    session: yaml-cookie
  proxy: http://127.0.0.1:8080
""".strip(),
                encoding="utf-8",
            )

            config = load_scan_config(path)

        self.assertEqual(config.target, "https://example.com")
        self.assertEqual(config.profile, "quick")
        self.assertEqual(config.mode, "passive")
        self.assertEqual(config.max_pages, 12)
        self.assertEqual(config.timeout, 4.0)
        self.assertEqual(config.output_dir, "reports/yaml")
        self.assertEqual(config.crawl_delay, 0.2)
        self.assertEqual(config.requests_per_second, 0.5)
        self.assertEqual(config.headers["User-Agent"], "SACS-Oreo-YAML-Test")
        self.assertEqual(config.cookies["session"], "yaml-cookie")
        self.assertEqual(config.proxy, "http://127.0.0.1:8080")

    def test_config_must_be_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oreo.yaml"
            path.write_text("- https://example.com\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "Scan config must be an object"):
                load_scan_config(path)

    def test_numeric_config_values_are_bounded(self):
        invalid_values = [
            ("max_pages", 0, "between 1 and 1000"),
            ("max_pages", 1001, "between 1 and 1000"),
            ("timeout", 0, "between 0.1 and 60"),
            ("timeout", 61, "between 0.1 and 60"),
            ("crawl_delay", -0.1, "between 0 and 60"),
            ("crawl_delay", 61, "between 0 and 60"),
            ("requests_per_second", 0, "between 0.1 and 20"),
            ("requests_per_second", 21, "between 0.1 and 20"),
        ]
        for field_name, value, message in invalid_values:
            with self.subTest(field_name=field_name, value=value):
                with self.assertRaisesRegex(ValueError, message):
                    resolve_scan_config(_scan_args(**{field_name: value}))

    def test_file_numeric_values_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oreo.toml"
            path.write_text(
                """
[scan]
target = "https://example.com"
max_pages = -1
""".strip(),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "max_pages.*between 1 and 1000"):
                resolve_scan_config(_scan_args(target=None, config=str(path)))

    def test_max_pages_must_be_an_integer(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oreo.toml"
            path.write_text(
                """
[scan]
target = "https://example.com"
max_pages = 1.5
""".strip(),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "max_pages.*integer"):
                load_scan_config(path)

    def test_boolean_numeric_config_values_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oreo.toml"
            path.write_text(
                """
[scan]
target = "https://example.com"
max_pages = true
""".strip(),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "max_pages.*integer"):
                load_scan_config(path)


if __name__ == "__main__":
    unittest.main()
