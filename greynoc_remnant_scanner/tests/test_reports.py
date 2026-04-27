from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from greynoc_mcafee_scanner.app import (
    Finding,
    build_json_payload,
    render_text_report,
    save_json_report,
    save_text_report,
    severity_counts,
)


class ReportTests(unittest.TestCase):
    def sample_findings(self) -> list[Finding]:
        return [
            Finding("Installed program", "McAfee Example", r"HKLM\Software\Example", "DisplayName=McAfee Example", "High"),
            Finding("Folder/file", "McAfee", r"C:\ProgramData\McAfee", "Exists", "Medium"),
        ]

    def test_severity_counts(self) -> None:
        counts = severity_counts(self.sample_findings())
        self.assertEqual(counts["High"], 1)
        self.assertEqual(counts["Medium"], 1)
        self.assertEqual(counts["Low"], 0)

    def test_text_report_contains_branding_and_findings(self) -> None:
        report = render_text_report(self.sample_findings())
        self.assertIn("GreyNOC McAfee Remnant Scanner Report", report)
        self.assertIn("Total findings: 2", report)
        self.assertIn("McAfee Example", report)

    def test_json_payload_is_structured(self) -> None:
        payload = build_json_payload(self.sample_findings())
        self.assertEqual(payload["total_findings"], 2)
        self.assertEqual(len(payload["findings"]), 2)

    def test_report_files_are_written(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            txt_path = Path(tmp) / "nested" / "report.txt"
            json_path = Path(tmp) / "nested" / "report.json"
            save_text_report(self.sample_findings(), txt_path)
            save_json_report(self.sample_findings(), json_path)
            self.assertTrue(txt_path.exists())
            self.assertTrue(json_path.exists())
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["total_findings"], 2)


if __name__ == "__main__":
    unittest.main()
