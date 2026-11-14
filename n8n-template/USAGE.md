# AAG n8n template — "Approve before agent sends email"

Built by Ingenious AI · MIT licensed · Wedge for
[Agent Auth Gateway](https://agentauth.getingeniousai.com)

**File:** `aag-approve-before-agent-sends-email.json` — import it in n8n
(Workflows → Import from File). 8 nodes, no credentials baked in.

## What it does
1. **Agent Action Webhook** receives the agent's attempted action
   (`POST /webhook/aag-agent-action` with `agent`, `action`, `to`,
   `subject`, `detail`, optional `request_id`).
2. **Build Approval Request** normalises it into one approval request.
3. **Slack Approval (Wait)** posts the request to `#agent-approvals`
   (set your Slack credential + channel after import).
4. **Wait for Human Decision** pauses the execution — nothing sends
   while it waits. Resume it with `decision=approved` (form submission,
   the AAG Slack app's buttons, or n8n's resume URL).
5. **Approved?** routes: approved → **Send Email** fires; anything else
   (denied / timeout / malformed) skips the send — fail-closed.
6. **Audit Log — Decision** emits exactly one JSON line per decision
   (the AAG evidence record; point it at your log store or the hosted
   gateway in production).
7. **Respond to Agent** returns `{request_id, decision}` to the caller.

## Setup (5 minutes)
- Add a Slack credential to the Slack node; pick your approvals channel.
- Add an SMTP credential to the Send Email node; set `fromEmail`.
- Activate the workflow. Point your agent at the production webhook URL
  instead of letting it send mail directly — that reroute *is* the gate.

## Notes
- The Wait node is the gate: an execution that is never resumed never
  sends. Set an n8n execution timeout if you want stale requests to
  expire into the denied branch's audit line.
- Variant idea (same skeleton): swap the webhook payload for a scheduled
  DNS check and the email node for an alert — "alert on DMARC failure"
  reuses nodes 1–4 and 6 unchanged.
