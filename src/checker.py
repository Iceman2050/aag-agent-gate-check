#!/usr/bin/env python3
"""
AAG Wedge Checker — Agent Auth Gateway distribution wedge.
Built by Ingenious AI. MIT licensed.

Fails CI when:
  (a) an AI-agent action lacks a human-approval gate, and/or
  (b) the sending domain's DMARC/SPF posture is broken.

Fail-closed DNS semantics (mirrors the fleet finding generator):
  - A DNS query that errors or returns unparseable data is UNVERIFIED,
    never assumed good. UNVERIFIED counts as a failure in strict mode
    (the default).
  - DMARC missing -> FAIL. DMARC p=none -> FAIL (monitor-only, no
    enforcement). p=quarantine -> WARN. p=reject -> PASS.
  - DMARC without rua= -> WARN (no aggregate reporting).
  - SPF missing -> FAIL. SPF ending ~all -> WARN (softfail).
    ?all -> FAIL (neutral, no enforcement). -all -> PASS.
  - SPF with >6 include: mechanisms -> WARN (10-lookup limit risk;
    full recursive count is UNVERIFIED without expansion).

Agent-action gate ruleset (documented in README.md, RULESET below):
  A file is scanned line-by-line for agent-action patterns. If an
  action pattern is found and NO approval-gate token exists in the
  same file (file-level gate) or within GATE_WINDOW lines of the
  action, the finding is a FAIL.

Usage:
  python3 checker.py [--root .] [--domain example.com] [--no-dns]
                     [--dns-json fixtures.json] [--format text|json]
                     [--warn-only]
Exit codes: 0 = pass, 1 = fail findings, 2 = usage / internal error.
Stdlib only. No network access except `dig` subprocess for DNS mode.
"""
import argparse, json, os, re, subprocess, sys

# ---------------------------------------------------------------- ruleset
# Action patterns: an agent (or automation acting for one) performing a
# consequential outbound action.
ACTION_PATTERNS = [
    (r"\bsend_email\b|\bsendmail\b|send_message.*email", "agent sends email"),
    (r"smtplib\.|SMTP\(|nodemailer|sendgrid.*send|mailgun.*send|resend.*emails\.send", "code sends email via a mail library/API"),
    (r"chat\.postMessage|slack.*post|webhook.*post", "agent posts to Slack / webhook"),
    (r"openai\.|anthropic\.|langchain|crewai|autogen|ChatOpenAI|gpt-4|claude-", "LLM / agent framework call"),
    (r"agent[_\.\s]*(send|post|publish|deploy|execute|run|act)\b", "generic agent action verb"),
    (r"requests\.post\(|httpx\.post\(|fetch\([^)]*method:\s*['\"]POST", "outbound HTTP POST"),
    (r"\bpublish\b.*\b(post|page|release)\b|create_pull_request|merge_pull_request", "agent publishes / merges"),
]
# Approval-gate tokens: presence in the same file counts as a gate.
GATE_TOKENS = [
    r"human[_-]?approval", r"require[_-]?approval", r"approval[_-]?gate",
    r"environment:\s*\S*(prod|production|release)",  # GH Actions env protection
    r"workflow_dispatch",  # manual trigger = human in the loop (weak gate, noted)
    r"\bapprover\b", r"\breview(ed|er)?\b.*\brequired\b",
    r"aag[_-]?gate", r"agentauth", r"slack[_-]?approv",
    r"manual[_-]?approval", r"confirm[_-]?before",
]
ACTION_RE = [(re.compile(p, re.I), label) for p, label in ACTION_PATTERNS]
GATE_RE = [re.compile(p, re.I) for p in GATE_TOKENS]
GATE_WINDOW = 15  # lines around an action where a gate token also counts
SCAN_EXTS = {".yml", ".yaml", ".json", ".py", ".js", ".ts", ".mjs", ".sh", ".toml"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "vendor", "tests", "fixtures"}
SKIP_FILES = {"checker.py"}  # never flag ourselves: we contain the patterns as data

def scan_files(root):
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn in SKIP_FILES or os.path.splitext(fn)[1].lower() not in SCAN_EXTS:
                continue
            path = os.path.join(dirpath, fn)
            try:
                lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
            except OSError as e:
                findings.append({"level": "FAIL", "kind": "unreadable",
                                 "file": path, "detail": f"UNVERIFIED: could not read file ({e})"})
                continue
            file_has_gate = any(g.search("\n".join(lines)) for g in GATE_RE)
            for i, line in enumerate(lines):
                for rx, label in ACTION_RE:
                    if rx.search(line):
                        near = "\n".join(lines[max(0, i-GATE_WINDOW): i+GATE_WINDOW+1])
                        near_gate = any(g.search(near) for g in GATE_RE)
                        if not file_has_gate and not near_gate:
                            findings.append({
                                "level": "FAIL", "kind": "missing-approval-gate",
                                "file": os.path.relpath(path, root), "line": i + 1,
                                "detail": f"{label} with no human-approval gate in file or within {GATE_WINDOW} lines",
                                "snippet": line.strip()[:160]})
                        break
    return findings

# ---------------------------------------------------------------- DNS
def _dig(qtype, name):
    try:
        r = subprocess.run(["dig", "+short", "+time=3", "+tries=1", qtype, name],
                           capture_output=True, text=True, timeout=8)
        return [l.strip().strip('"') for l in r.stdout.splitlines() if l.strip()], r.returncode
    except Exception as e:
        return None, f"ERROR: {e}"

def dns_records(domain, dns_json=None):
    """Return {'dmarc': str|None|'UNVERIFIED', 'spf': str|None|'UNVERIFIED'}.
    dns_json (tests/offline): {'dmarc_txt': [...], 'root_txt': [...]}."""
    if dns_json is not None:
        dmarc = next((l for l in dns_json.get("dmarc_txt", []) if "v=DMARC1" in l), None)
        spf = next((l for l in dns_json.get("root_txt", []) if "v=spf1" in l.lower()), None)
        return {"dmarc": dmarc, "spf": spf}
    dmarc_lines, rc1 = _dig("TXT", f"_dmarc.{domain}")
    root_lines, rc2 = _dig("TXT", domain)
    if dmarc_lines is None or root_lines is None:
        return {"dmarc": "UNVERIFIED", "spf": "UNVERIFIED"}
    dmarc = next((l for l in dmarc_lines if "v=DMARC1" in l), None)
    if dmarc_lines and dmarc is None:
        dmarc = "UNVERIFIED"  # data returned but no v=DMARC1 — do not guess
    spf = next((l for l in root_lines if "v=spf1" in l.lower()), None)
    return {"dmarc": dmarc, "spf": spf}

def dns_findings(domain, rec):
    out = []
    d, s = rec["dmarc"], rec["spf"]
    if d == "UNVERIFIED":
        out.append({"level": "FAIL", "kind": "dmarc-unverified", "detail": "DMARC lookup UNVERIFIED (fail-closed)"})
    elif d is None:
        out.append({"level": "FAIL", "kind": "dmarc-missing", "detail": f"No DMARC record at _dmarc.{domain} — anyone can spoof this sending domain"})
    elif "p=none" in d:
        out.append({"level": "FAIL", "kind": "dmarc-none", "detail": f"DMARC is monitor-only (p=none): `{d}` — failing mail is still delivered"})
    elif "p=quarantine" in d:
        out.append({"level": "WARN", "kind": "dmarc-quarantine", "detail": f"DMARC p=quarantine: `{d}` — enforcement, weaker than reject"})
    elif "p=reject" in d:
        out.append({"level": "PASS", "kind": "dmarc-reject", "detail": f"DMARC p=reject: `{d}`"})
    if d not in (None, "UNVERIFIED") and "rua=" not in str(d):
        out.append({"level": "WARN", "kind": "dmarc-no-rua", "detail": "DMARC has no rua= reporting address — spoofing attempts are invisible"})
    if s == "UNVERIFIED":
        out.append({"level": "FAIL", "kind": "spf-unverified", "detail": "SPF lookup UNVERIFIED (fail-closed)"})
    elif s is None:
        out.append({"level": "FAIL", "kind": "spf-missing", "detail": f"No SPF (v=spf1) record on {domain}"})
    elif s.strip().endswith("~all"):
        out.append({"level": "WARN", "kind": "spf-softfail", "detail": f"SPF ends ~all (softfail): `{s}`"})
    elif "?all" in s:
        out.append({"level": "FAIL", "kind": "spf-neutral", "detail": f"SPF ends ?all (neutral, no enforcement): `{s}`"})
    elif s.strip().endswith("-all"):
        out.append({"level": "PASS", "kind": "spf-hardfail", "detail": f"SPF ends -all (hard fail): `{s}`"})
    if s not in (None, "UNVERIFIED") and str(s).count("include:") > 6:
        out.append({"level": "WARN", "kind": "spf-includes", "detail": f"SPF has {str(s).count('include:')} include: mechanisms — check the 10 DNS-lookup limit (recursive count UNVERIFIED here)"})
    return out

def main(argv=None):
    ap = argparse.ArgumentParser(description="AAG wedge checker: approval gates + DMARC/SPF posture")
    ap.add_argument("--root", default=".")
    ap.add_argument("--domain", default=None, help="Sending domain to check (enables DNS checks)")
    ap.add_argument("--no-dns", action="store_true")
    ap.add_argument("--dns-json", default=None, help="Offline/test DNS fixture JSON")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--warn-only", action="store_true", help="Never exit 1 (report only)")
    a = ap.parse_args(argv)
    findings = scan_files(a.root)
    if a.domain and not a.no_dns:
        fixture = json.load(open(a.dns_json)) if a.dns_json else None
        findings += dns_findings(a.domain, dns_records(a.domain, fixture))
    fails = [f for f in findings if f["level"] == "FAIL"]
    if a.format == "json":
        print(json.dumps({"findings": findings, "fail_count": len(fails)}, indent=2))
    else:
        for f in findings:
            loc = f.get("file", a.domain or "")
            if "line" in f: loc += f":{f['line']}"
            print(f"[{f['level']}] {f['kind']} {loc} — {f['detail']}")
        print(f"\nAAG checker: {len(fails)} FAIL, {sum(1 for f in findings if f['level']=='WARN')} WARN, "
              f"{sum(1 for f in findings if f['level']=='PASS')} PASS")
        print("Hosted controls & approvals for agent actions: https://agentauth.getingeniousai.com")
    return 0 if (a.warn_only or not fails) else 1

if __name__ == "__main__":
    sys.exit(main())
