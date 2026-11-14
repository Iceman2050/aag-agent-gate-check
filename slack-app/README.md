# AAG Slack Approval App — reference implementation

Built by Ingenious AI · MIT licensed · Wedge for [Agent Auth Gateway](https://agentauth.getingeniousai.com)

Routes an AI-agent action to a Slack channel for **Approve / Deny**, verifies
every Slack request signature (HMAC-SHA256, v0, 5-minute replay window,
fail-closed), and writes **one JSON audit-log line per decision** — the
evidence record that ties back to the hosted Agent Auth Gateway.

## Why stdlib HTTP, not Bolt
Zero dependencies: `src/app.py` runs on any Python 3.10+ host with no
install step. The signature check (`verify_signature`) and the decision
handler (`handle_decision`) are framework-free, so a Bolt app can import
them unchanged.

## Run
```bash
export SLACK_SIGNING_SECRET=...   # from your Slack app's Basic Information
export SLACK_BOT_TOKEN=xoxb-...   # after installing the app to a workspace
python3 src/app.py                # listens on :3000 (PORT overridable)
```
Create the Slack app from `manifest.json` (api.slack.com/apps → Create New
App → From a manifest), then point its Interactivity request URL at
`https://YOUR-HOST/slack/actions`.

## Use
```bash
# Ask a human before the agent acts:
curl -X POST localhost:3000/aag/request -H 'Content-Type: application/json' -d '{
  "channel": "#agent-approvals", "agent": "mailer-1",
  "action": "send_email", "detail": "Weekly summary to 42 customers",
  "request_id": "run-2026-11-14-001"}'
# A human clicks Approve or Deny in Slack; the decision lands in the
# audit log (AAG_AUDIT_LOG, default ./aag-audit.log), one line per decision:
# {"ts": "...", "source": "aag-slack-approval-app", "event": "decision",
#  "decision": "approved", "request_id": "run-2026-11-14-001", ...}
```

## Scope
Build-only wedge. **Slack Marketplace listing is out of scope** (it waits
for pilot users). The hosted gateway at agentauth.getingeniousai.com adds
policies, roles, and retention on top of this pattern; the $497 AAG
assessment is the ruled hosted offer.

## Tests
```bash
python3 -m unittest discover -s tests -v
```
