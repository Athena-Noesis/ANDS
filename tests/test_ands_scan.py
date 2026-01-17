import json
import unittest
from unittest.mock import patch, MagicMock
from tools.ands_scan import Evidence, ProbeResult, ScanReport, infer_ands, verify_declaration_signature, normalize_base_url

class TestAndsScanCore(unittest.TestCase):

    def test_normalize_base_url(self):
        self.assertEqual(normalize_base_url("example.com"), "https://example.com/")
        self.assertEqual(normalize_base_url("http://test.com"), "http://test.com/")
        self.assertEqual(normalize_base_url("https://test.com/"), "https://test.com/")

    def test_infer_ands_baseline(self):
        hints = []
        evidence = []
        gaps = []
        ands, conf, reasoning = infer_ands(hints, evidence, gaps)
        self.assertEqual(ands, "2.1.1.1.3.0")
        self.assertAlmostEqual(conf, 0.2)

    def test_infer_ands_with_hints(self):
        hints = ["rbac_surface", "code_execution_surface"]
        evidence = []
        gaps = []
        ands, conf, reasoning = infer_ands(hints, evidence, gaps)
        # R should be 5 for code execution (in 5th position)
        parts = ands.split('.')
        self.assertEqual(parts[4], "5")
        # G should be 2 for rbac
        self.assertEqual(ands.split(".")[3], "2")
        # Evidence should have been added
        self.assertEqual(len(evidence), 2)
        # Confidence should be higher
        self.assertGreater(conf, 0.2)

    def test_verify_declaration_signature_missing(self):
        doc = {"ands": "1.0.0.0.0"}
        ok, msg = verify_declaration_signature(doc)
        self.assertFalse(ok)
        self.assertIn("Missing 'signed' block", msg)

    def test_verify_declaration_signature_invalid_alg(self):
        doc = {
            "ands": "1.0.0.0.0",
            "signed": {"alg": "rsa", "sig": "...", "pubkey": "..."}
        }
        ok, msg = verify_declaration_signature(doc)
        self.assertFalse(ok)
        self.assertIn("Unsupported algorithm", msg)

if __name__ == "__main__":
    unittest.main()
