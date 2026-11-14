#!/usr/bin/env python3
"""Tests for the AAG wedge checker. Stdlib unittest; run: python3 -m unittest discover -s tests -v"""
import json, os, subprocess, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))
import checker  # noqa: E402

FIX = os.path.join(HERE, "fixtures")

class TestGateScan(unittest.TestCase):
    def test_ungated_agent_fails(self):
        f = checker.scan_files(os.path.join(FIX, "fail-ungated"))
        self.assertTrue(any(x["kind"] == "missing-approval-gate" for x in f), f)

    def test_gated_workflow_passes(self):
        f = checker.scan_files(os.path.join(FIX, "pass-gated"))
        self.assertFalse([x for x in f if x["level"] == "FAIL"], f)

class TestDNS(unittest.TestCase):
    def _load(self, name):
        return json.load(open(os.path.join(FIX, name)))
    def test_good_posture_passes(self):
        rec = checker.dns_records("example.com", self._load("dns-good.json"))
        f = checker.dns_findings("example.com", rec)
        self.assertFalse([x for x in f if x["level"] == "FAIL"], f)
        self.assertTrue(any(x["kind"] == "dmarc-reject" for x in f))
    def test_bad_posture_fails(self):
        rec = checker.dns_records("example.com", self._load("dns-bad.json"))
        f = checker.dns_findings("example.com", rec)
        kinds = {x["kind"] for x in f if x["level"] == "FAIL"}
        self.assertIn("dmarc-none", kinds); self.assertIn("spf-missing", kinds)
    def test_unverified_is_fail_closed(self):
        f = checker.dns_findings("example.com", {"dmarc": "UNVERIFIED", "spf": "UNVERIFIED"})
        self.assertEqual(2, len([x for x in f if x["level"] == "FAIL"]))

class TestCLI(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run([sys.executable, os.path.join(ROOT, "src", "checker.py"), *args],
                              capture_output=True, text=True)
    def test_cli_ungated_exits_1(self):
        r = self._run("--root", os.path.join(FIX, "fail-ungated"), "--no-dns")
        self.assertEqual(1, r.returncode, r.stdout + r.stderr)
    def test_cli_gated_good_dns_exits_0(self):
        r = self._run("--root", os.path.join(FIX, "pass-gated"), "--domain", "example.com",
                      "--dns-json", os.path.join(FIX, "dns-good.json"))
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
    def test_cli_bad_dns_exits_1(self):
        r = self._run("--root", os.path.join(FIX, "pass-gated"), "--domain", "example.com",
                      "--dns-json", os.path.join(FIX, "dns-bad.json"))
        self.assertEqual(1, r.returncode, r.stdout + r.stderr)

if __name__ == "__main__":
    unittest.main()
