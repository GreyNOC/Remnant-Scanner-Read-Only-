from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from greynoc_mcafee_scanner.app import Finding, run_cli


class CliTests(unittest.TestCase):
    @patch("greynoc_mcafee_scanner.app.scan_system")
    def test_cli_writes_reports(self, scan_system) -> None:
        scan_system.return_value = [Finding("Folder/file", "McAfee", r"C:\ProgramData\McAfee", "Exists", "Medium")]
        with tempfile.TemporaryDirectory() as tmp:
            txt = Path(tmp) / "report.txt"
            js = Path(tmp) / "report.json"
            code = run_cli(["--cli", "--txt", str(txt), "--json", str(js)])
            self.assertEqual(code, 0)
            self.assertTrue(txt.exists())
            self.assertTrue(js.exists())

    @patch("greynoc_mcafee_scanner.app.scan_system")
    def test_cli_fail_on_findings_is_opt_in(self, scan_system) -> None:
        scan_system.return_value = [Finding("Folder/file", "McAfee", r"C:\ProgramData\McAfee", "Exists", "Medium")]
        self.assertEqual(run_cli(["--cli"]), 0)
        self.assertEqual(run_cli(["--cli", "--fail-on-findings"]), 1)


if __name__ == "__main__":
    unittest.main()
