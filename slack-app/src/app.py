#!/usr/bin/env python3
"""
AAG Slack approval app — reference implementation (stdlib only).
Built by Ingenious AI. MIT licensed.

Routes an AI-agent action to a Slack channel for Approve / Deny.
Every decision writes ONE audit-log line (JSON) — the evidence record
that ties back to Agent Auth Gateway (https://agentauth.getingeniousai.com).

Design choice: plain webhook-verified HTTP handler on Python stdlib
(http.server) instead of Slack Bolt — zero dependencies, runs anywhere,
and matches the fleet's dependency-light pattern. Slack Bolt users can
port handle_decision() directly; the signature + audit core is identical.

Env:
  SLACK_SIGNING_SECRET  (required) Slack app signing secret
  SLACK_BOT_TOKEN       (required to post approval requests) xoxb-...
  AAG_AUDIT_LOG         audit log path (default ./aag-audit.log)
  PORT                  listen port (default 3000)

Endpoints:
  POST /aag/request    JSON {action, agent, detail, request_id?} -> posts
                       an Approve/Deny message to `channel` in the body
  POST /slack/actions  Slack interactive payload (block_actions) ->
                       verifies signature, records decision, replies
  GET  /health         200 ok
"""
import hashlib, hmac, json, os, sys, time, urllib.request, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

SIGNING_SECRET = os.environ.get("SLACK_SIGNING_SECRET", "")
AUDIT_LOG = os.environ.get("AAG_AUDIT_LOG", "./aag-audit.log")
REPLAY_WINDOW_S = 300  # Slack's recommended 5-minute tolerance

def verify_signature(timestamp: str, body: bytes, signature: str, secret: str = None, now: float = None) -> bool:
    """Slack v0 signature check. Fail-closed: any anomaly -> False."""
    secret = SIGNING_SECRET if secret is None else secret
    if not secret or not timestamp or not signature:
        return False
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs((now if now is not None else time.time()) - ts) > REPLAY_WINDOW_S:
        return False
    base = b"v0:" + timestamp.encode() + b":" + body
    expected = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

def audit(event: dict, path: str = None):
    """One JSON line per decision/event — the AAG evidence tie-in."""
    line = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": "aag-slack-approval-app", **event}
    with open(path or AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(line) + "\n")
    return line

def approval_blocks(req: dict) -> list:
    rid = req.get("request_id") or uuid.uuid4().hex[:12]
    return [
        {"type": "section", "text": {"type": "mrkdwn",
         "text": f":robot_face: *Agent action needs approval*\n*Agent:* {req.get('agent','unknown')}\n"
                 f"*Action:* {req.get('action','(unspecified)')}\n*Detail:* {req.get('detail','')}\n*Request:* `{rid}`"}},
        {"type": "actions", "block_id": f"aag_{rid}", "elements": [
            {"type": "button", "style": "primary", "text": {"type": "plain_text", "text": "Approve"},
             "action_id": "aag_approve", "value": rid},
            {"type": "button", "style": "danger", "text": {"type": "plain_text", "text": "Deny"},
             "action_id": "aag_deny", "value": rid}]}]

def handle_decision(payload: dict, audit_path: str = None) -> dict:
    """Process a Slack block_actions payload. Returns the audit line.
    Raises ValueError on a malformed / non-AAG payload (fail-closed)."""
    actions = payload.get("actions") or []
    if len(actions) != 1 or actions[0].get("action_id") not in ("aag_approve", "aag_deny"):
        raise ValueError("not an AAG decision payload")
    a = actions[0]
    decision = "approved" if a["action_id"] == "aag_approve" else "denied"
    return audit({
        "event": "decision", "decision": decision,
        "request_id": a.get("value"),
        "decided_by": (payload.get("user") or {}).get("id"),
        "channel": (payload.get("channel") or {}).get("id"),
        "action_id": a["action_id"],
    }, path=audit_path)

def post_to_slack(channel: str, req: dict, token: str = None) -> dict:
    token = token or os.environ.get("SLACK_BOT_TOKEN", "")
    body = json.dumps({"channel": channel, "text": f"Agent action needs approval: {req.get('action','')}",
                       "blocks": approval_blocks(req)}).encode()
    r = urllib.request.Request("https://slack.com/api/chat.postMessage", data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json; charset=utf-8"})
    with urllib.request.urlopen(r, timeout=10) as resp:
        return json.loads(resp.read())

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        self._send(200, {"ok": True}) if self.path == "/health" else self._send(404, {"ok": False})
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path == "/slack/actions":
            if not verify_signature(self.headers.get("X-Slack-Request-Timestamp", ""), body,
                                    self.headers.get("X-Slack-Signature", "")):
                return self._send(401, {"ok": False, "error": "bad signature"})
            form = parse_qs(body.decode())
            try:
                payload = json.loads(form["payload"][0])
                line = handle_decision(payload)
            except Exception as e:
                return self._send(400, {"ok": False, "error": str(e)})
            return self._send(200, {"ok": True, "decision": line["decision"]})
        if self.path == "/aag/request":
            try:
                req = json.loads(body)
                audit({"event": "requested", "request_id": req.get("request_id"),
                       "agent": req.get("agent"), "action": req.get("action")})
                res = post_to_slack(req["channel"], req)
            except Exception as e:
                return self._send(400, {"ok": False, "error": str(e)})
            return self._send(200, {"ok": bool(res.get("ok")), "slack": res})
        self._send(404, {"ok": False})

if __name__ == "__main__":
    if not SIGNING_SECRET:
        sys.exit("SLACK_SIGNING_SECRET is required (fail-closed: refusing to run unverified)")
    HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "3000"))), Handler).serve_forever()
