#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Oxytis Forensics
"""Call Oxytis Powertrain /api/finding/analyze (and /cve/analyze) without Burp.

    from powertrain import assess_finding
    r = assess_finding("Reflected XSS in /search q param ...", token=TOKEN)

CLI:  echo "finding text" | python3 powertrain.py --token TOKEN
      python3 powertrain.py --cve CVE-2024-3094 --token TOKEN
"""
import argparse, json, os, re, sys, urllib.request

API_URL = "https://oxytis.com/api/cve/analyze"

# Same client-side redaction as the Burp extension (v1.4) so the same rules apply here.
_SENSITIVE_KEY_NAMES = (r"pass(?:word|wd)?|pwd|secret|token|api[_-]?key|auth|session|sid|jsessionid|"
                        r"phpsessid|csrf|xsrf|nonce|otp|ssn|email|user(?:name)?|login|account|card|cvv|iban")
_SENSITIVE_KV = re.compile(r'(?i)(["\']?\b(?:' + _SENSITIVE_KEY_NAMES + r')\b["\']?\s*[:=]\s*["\']?)([^"\'&;\s,]+)')
_PRIOR_ASSESSMENT = re.compile(r"(?im)^(CVSS v4\.0:|OWASP Category:|CWE-\d+:).*$\n?")


def redact(text, host=None):
    if not text:
        return ""
    t = text
    if host:
        t = re.sub(re.escape(host), "[host]", t, flags=re.I)
    t = re.sub(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", "[jwt]", t)
    t = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[email]", t)
    t = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[ipv4]", t)
    t = re.sub(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", "[mac]", t)
    t = re.sub(r"(?i)(serial(?:\s*(?:number|no\.?|#))?\s*[:=(]?\s*)([A-Za-z0-9][A-Za-z0-9-]{3,})",
               lambda m: m.group(1) + "[serial]", t)
    t = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "[uuid]", t)
    t = re.sub(r"\b[0-9a-fA-F]{32,}\b", lambda m: "[hex:%d]" % len(m.group(0)), t)
    t = re.sub(r"(?<![A-Za-z0-9+/=])(?=[A-Za-z0-9+/]*\d)[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])",
               lambda m: "[b64:%d]" % len(m.group(0)), t)
    return _SENSITIVE_KV.sub(lambda m: m.group(1) + "[redacted]", t)


def _post(url, payload, timeout=60):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def assess_finding(finding, token=None, name=None, cwe=None, evidence="", host=None,
                   exposure="external", controls="partial", mode="redacted", api_url=API_URL):
    """finding: free-text finding. First line is used as the name unless `name` is given.
    cwe=None lets the model infer. mode: redacted | metadata-only | raw."""
    token = token or os.environ.get("POWERTRAIN_TOKEN")
    if not token:
        raise ValueError("token required (arg or POWERTRAIN_TOKEN)")
    finding = _PRIOR_ASSESSMENT.sub("", finding).strip()
    if name is None:
        name, _, rest = finding.partition("\n")
        detail = rest.strip() or name
    else:
        detail = finding
    if mode != "raw":
        detail = redact(detail, host)
        evidence = redact(evidence, host) if mode == "redacted" else ""
    payload = {
        "token": token, "name": name.strip(), "cwe": cwe, "detail": detail,
        "evidence": evidence or "(no request/response captured)",
        "evidence_mode": mode, "exposure": exposure, "controls": controls,
    }
    return _post(api_url.replace("/cve/", "/finding/"), payload)


def analyze_cve(cve_id, token=None, api_url=API_URL):
    token = token or os.environ.get("POWERTRAIN_TOKEN")
    return _post(api_url, {"token": token, "cve_id": cve_id, "format": "json"}, timeout=30)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", default=os.environ.get("POWERTRAIN_TOKEN"))
    ap.add_argument("--cve")
    ap.add_argument("--name")
    ap.add_argument("--cwe")
    ap.add_argument("--exposure", default="external", choices=["external", "internal", "unknown"])
    ap.add_argument("--controls", default="partial", choices=["partial", "ineffective", "effective"])
    ap.add_argument("--mode", default="redacted", choices=["redacted", "metadata-only", "raw"])
    ap.add_argument("--evidence", help="file containing request/response evidence")
    ap.add_argument("--url", default=API_URL)
    ap.add_argument("finding", nargs="?", help="finding text (or stdin)")
    a = ap.parse_args()
    if a.cve:
        out = analyze_cve(a.cve, a.token, a.url)
    else:
        text = a.finding or sys.stdin.read()
        ev = open(a.evidence).read() if a.evidence else ""
        out = assess_finding(text, a.token, a.name, a.cwe, ev, exposure=a.exposure,
                             controls=a.controls, mode=a.mode, api_url=a.url)
    print(json.dumps(out, indent=2))
