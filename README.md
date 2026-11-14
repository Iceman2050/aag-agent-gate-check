# AAG Agent-Action Gate Check — GitHub Action

Built by Ingenious AI · MIT licensed · Free wedge for
[Agent Auth Gateway](https://agentauth.getingeniousai.com)

Fails your CI when:

1. **An AI-agent action has no human-approval gate** — the checker scans
   workflow / config / code files for agent-action patterns (LLM calls,
   email sends, Slack posts, outbound POSTs, publish/merge actions) and
   fails if no approval-gate token exists in the same file or within
   15 lines of the action.
2. **Your sending domain's DMARC/SPF posture is broken** — with `domain`
   set, the checker reads live DNS (`dig`) and applies fail-closed rules:
   a lookup that errors or returns unparseable data is **UNVERIFIED, and
   UNVERIFIED fails** — it is never assumed good.

## Quick start

```yaml
# .github/workflows/aag-check.yml
name: AAG check
on: [push, pull_request]
jobs:
  aag:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Iceman2050/aag-agent-gate-check@v1   # (repo name at publish time)
        with:
          domain: example.com        # your sending domain
          # path: .                  # default
          # warn-only: "true"        # report without failing, while you adopt
```

Run it locally with no install (Python 3.10+, stdlib only):

```bash
python3 src/checker.py --root . --domain example.com
python3 src/checker.py --root . --no-dns            # gate scan only
python3 src/checker.py --root . --domain example.com --format json
```

## The ruleset

**Gate scan** — action patterns (regex, case-insensitive): LLM/agent
framework calls (`openai.`, `anthropic.`, `langchain`, `crewai`,
`gpt-4`, `claude-`, …), email sends (`send_email`, `smtplib`, `SMTP(`,
`nodemailer`, SendGrid/Mailgun/Resend send calls), Slack/webhook posts,
outbound `POST`s, publish/merge calls, generic `agent.<verb>` actions.
Gate tokens that satisfy a finding: `human-approval` / `require-approval`
/ `approval-gate`, a protected GitHub `environment:` (prod/production/
release), `workflow_dispatch` (manual trigger), `aag-gate`, `agentauth`,
`slack-approv…`, `manual-approval`, `confirm-before`, a required reviewer.
Files under `tests/`, `fixtures/`, `node_modules/`, `.git/` are skipped.

**DNS posture** (mirrors the fleet finding-generator semantics):

| Check | Result |
|---|---|
| No DMARC record | FAIL |
| DMARC `p=none` | FAIL — monitor-only, spoofed mail still delivered |
| DMARC `p=quarantine` | WARN |
| DMARC `p=reject` | PASS |
| DMARC without `rua=` | WARN — no aggregate reporting |
| No SPF record | FAIL |
| SPF `?all` | FAIL — neutral, no enforcement |
| SPF `~all` | WARN — softfail |
| SPF `-all` | PASS |
| SPF > 6 `include:` | WARN — check the 10-lookup limit |
| DNS error / unparseable | FAIL — UNVERIFIED, fail-closed |

## Worked examples

**Failing** — ungated agent (`tests/fixtures/fail-ungated/agent.py`):

```
[FAIL] missing-approval-gate agent.py:3 — LLM / agent framework call with no human-approval gate in file or within 15 lines
[FAIL] missing-approval-gate agent.py:5 — code sends email via a mail library/API with no human-approval gate ...
AAG checker: 2 FAIL, 0 WARN, 0 PASS   → exit 1, CI goes red
```

**Passing** — same flow behind a protected environment
(`tests/fixtures/pass-gated/workflow.yml` uses `environment: production`
+ `human-approval`), with a healthy domain fixture:

```
[PASS] dmarc-reject  — DMARC p=reject: `v=DMARC1; p=reject; rua=mailto:dmarc@example.com`
[PASS] spf-hardfail  — SPF ends -all (hard fail): `v=spf1 include:_spf.google.com -all`
AAG checker: 0 FAIL, 0 WARN, 2 PASS   → exit 0
```

**Broken posture** (`tests/fixtures/dns-bad.json`): DMARC `p=none` → FAIL
`dmarc-none`; no SPF → FAIL `spf-missing`; no `rua=` → WARN. Exit 1.

## Tests

```bash
python3 -m unittest discover -s tests -v
```
Fixtures cover gated/ungated scans, good/bad DNS posture, UNVERIFIED
fail-closed behaviour, and CLI exit codes. DNS tests run offline against
JSON fixtures (`--dns-json`); live runs use `dig`.

## Going further
This checker is the free wedge. The hosted
[Agent Auth Gateway](https://agentauth.getingeniousai.com) adds runtime
approval routing (Slack included), policies, roles, and a retained audit
trail across all your agents — the $497 AAG assessment is the starting
offer.
