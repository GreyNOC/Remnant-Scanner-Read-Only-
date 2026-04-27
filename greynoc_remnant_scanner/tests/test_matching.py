from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from greynoc_mcafee_scanner.app import looks_like_mcafee_service, text_contains_keyword


class MatchingTests(unittest.TestCase):
    def test_keyword_matching_detects_mcafee_terms(self) -> None:
        self.assertTrue(text_contains_keyword("McAfee Total Protection"))
        self.assertTrue(text_contains_keyword("WebAdvisor scheduled task"))
        self.assertTrue(text_contains_keyword("Publisher", "McAfee, LLC"))

    def test_keyword_matching_ignores_unrelated_text(self) -> None:
        self.assertFalse(text_contains_keyword("Windows Defender Antivirus"))

    def test_service_prefix_matching(self) -> None:
        self.assertTrue(looks_like_mcafee_service("mfevtp"))
        self.assertTrue(looks_like_mcafee_service("ExampleService", "McAfee firewall driver"))
        self.assertFalse(looks_like_mcafee_service("spooler"))


if __name__ == "__main__":
    unittest.main()
