from __future__ import annotations

import json
import os
from typing import Any

from openai import OpenAI

from scanner.base import Finding

SYSTEM_PROMPT = """You are KYA (Know Your Adversary), an elite web application security framework.
Your philosophy: the best person to lock a door is the one who knows how to pick it.
You map real offensive tradecraft -- drawn from OWASP Top 10, CWE classifications, and HTB CBBH/CPTS methodology -- to precise defensive controls.

You are given raw scanner findings from a web application audit. For each finding that is VULNERABLE or MISCONFIGURED:

1. Assess actual exploitability -- is this a real exploit path or just a misconfiguration that needs context?
2. Describe the full attacker exploit chain using HTB/CBBH tradecraft (step-by-step, as an attacker would actually do it)
3. Map to the OWASP Top 10 category and the most relevant CWE number
4. Cite the CBBH module this technique comes from (e.g. "CBBH Module 16: File Inclusion")
5. Give the single most effective hardening control, then list additional prevention layers

For reference, key CBBH prevention controls include:
- LFI/RFI: open_basedir in php.ini; allow_url_include=Off; never pass user input to include(); use whitelist map
- File Upload: whitelist extensions only; validate Content-Type AND magic bytes; rename files; serve via download.php not direct path; disable exec/system in php.ini
- XXE: disable external entity processing; disable DTD references; update XML libraries; switch to JSON/REST
- Auth: lockout after 5 attempts; opaque session IDs; HMAC-signed tokens; MFA for admin; remove default creds
- Verb Tampering: restrict methods in BOTH server config and application code; use global auth middleware
- SSRF: whitelist allowed URL destinations; block private IP ranges; disable unnecessary URL-fetching
- Headers: CSP default-src 'self'; HSTS max-age=31536000; X-Frame-Options DENY; X-Content-Type-Options nosniff

Return ONLY a valid JSON array (no markdown, no explanation outside the JSON) sorted by severity (Critical first).
Each item must have these exact keys:
{
  "severity": "Critical|High|Medium|Low|Info",
  "check": "name of the check",
  "is_exploitable": true/false,
  "exploit_path": "step-by-step attacker chain",
  "owasp_category": "e.g. A03:2021 Injection",
  "cwe": "e.g. CWE-22",
  "cbbh_module": "e.g. CBBH Module 16: File Inclusion",
  "hardening_control": "the primary fix",
  "prevention_layers": ["layer1", "layer2", "layer3"]
}"""


def analyze(findings: list[Finding], model: str | None = None) -> list[dict[str, Any]]:
    """Send scan findings to OpenRouter and return structured KYA report."""
    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        raise ValueError(
            "OPENROUTER_API_KEY is not set. Copy .env.example to .env and add your key."
        )

    if model is None:
        model = os.environ.get("OPENROUTER_MODEL", "anthropic/claude-haiku-4-5")

    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )

    # Filter to only actionable findings
    actionable = [f for f in findings if f.result in ("VULNERABLE", "MISCONFIGURED")]
    info_findings = [f for f in findings if f.result == "INFO"]

    if not actionable:
        return [{
            "severity": "Info",
            "check": "Overall",
            "is_exploitable": False,
            "exploit_path": "No vulnerabilities or misconfigurations detected by automated scan.",
            "owasp_category": "N/A",
            "cwe": "N/A",
            "cbbh_module": "N/A",
            "hardening_control": "Maintain current security posture and schedule regular re-tests.",
            "prevention_layers": [
                "Run authenticated scans for deeper coverage",
                "Manually test business logic flaws not detectable by automation",
                "Review source code for second-order vulnerabilities",
            ],
        }]

    findings_payload = json.dumps(
        [f.to_dict() for f in actionable],
        indent=2
    )

    user_message = f"""Analyze these web application scan findings and produce a KYA hardening report:

{findings_payload}

Additional context -- checks that returned INFO (no vulnerability confirmed):
{json.dumps([f.check for f in info_findings])}

Return ONLY the JSON array as specified."""

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
        temperature=0.2,
        max_tokens=4096,
    )

    raw = response.choices[0].message.content or "[]"

    # Strip any markdown code fences the model might add
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("```", 2)[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.rsplit("```", 1)[0].strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Fallback: return raw findings without AI enrichment
        return [
            {
                "severity": f.severity,
                "check": f.check,
                "is_exploitable": f.result == "VULNERABLE",
                "exploit_path": f.detail or f.evidence,
                "owasp_category": "See OWASP Top 10",
                "cwe": "See finding detail",
                "cbbh_module": "See KYA documentation",
                "hardening_control": f.detail,
                "prevention_layers": [],
            }
            for f in actionable
        ]
