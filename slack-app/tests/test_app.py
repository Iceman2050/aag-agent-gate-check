#!/usr/bin/env python3
"""Tests: signature verification + approve/deny handling with mocked Slack payloads.
Run: python3 -m unittest discover -s tests -v  (stdlib only)"""
import hashlib, hmac, json, os, sys, tempfile, time, unittest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import app  # noqa: E402

SECRET = "test-signing-secret"

def sign(ts: str, body: bytes, secret: str = SECRET) -> str:
    base = b"v0:" + ts.encode() + b":" + body
    return "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()

def payload(action_id, value="req123"):
    return {"type": "block_actions", "user": {"id": "U123"}, "channel": {"id": "C123"},
            "actions": [{"action_id": action_id, "value": value}]}

class TestSignature(unittest.TestCase):
    def test_valid_signature_passes(self):
        ts = str(int(time.time())); body = b"payload=%7B%7D"
        self.assertTrue(app.verify_signature(ts, body, sign(ts, body), secret=SECRET))
    def test_tampered_body_fails(self):
        ts = str(int(time.time()))
        self.assertFalse(app.verify_signature(ts, b"tampered", sign(ts, b"original"), secret=SECRET))
    def test_wrong_secret_fails(self):
        ts = str(int(time.time())); body = b"x"
        self.assertFalse(app.verify_signature(ts, body, sign(ts, body, "nope"), secret=SECRET))
    def test_stale_timestamp_fails(self):
        ts = str(int(time.time()) - 3600); body = b"x"
        self.assertFalse(app.verify_signature(ts, body, sign(ts, body), secret=SECRET))
    def test_missing_inputs_fail_closed(self):
        self.assertFalse(app.verify_signature("", b"x", "", secret=SECRET))

class TestDecisions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False); self.tmp.close()
    def _lines(self):
        return [json.loads(l) for l in open(self.tmp.name) if l.strip()]
    def test_approve_writes_audit_line(self):
        line = app.handle_decision(payload("aag_approve"), audit_path=self.tmp.name)
        self.assertEqual("approved", line["decision"]); self.assertEqual("req123", line["request_id"])
        self.assertEqual("U123", line["decided_by"]); self.assertEqual(1, len(self._lines()))
    def test_deny_writes_audit_line(self):
        line = app.handle_decision(payload("aag_deny", "req9"), audit_path=self.tmp.name)
        self.assertEqual("denied", line["decision"]); self.assertEqual("req9", line["request_id"])
    def test_non_aag_payload_rejected(self):
        with self.assertRaises(ValueError):
            app.handle_decision(payload("some_other_action"), audit_path=self.tmp.name)
        self.assertEqual(0, len(self._lines()))
    def test_blocks_shape(self):
        blocks = app.approval_blocks({"agent": "mailer", "action": "send_email", "request_id": "r1"})
        ids = [e["action_id"] for e in blocks[1]["elements"]]
        self.assertEqual(["aag_approve", "aag_deny"], ids)

if __name__ == "__main__":
    unittest.main()
