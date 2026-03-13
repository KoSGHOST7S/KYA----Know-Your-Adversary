from __future__ import annotations

import requests

from .base import BaseScanModule, Finding

DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}

# Endpoints commonly protected by authentication to test HEAD bypass
AUTH_ENDPOINTS = [
    "/admin", "/admin/", "/dashboard", "/api/admin",
    "/api/users", "/config", "/manage", "/panel",
]


class VerbTamperScanner(BaseScanModule):
    name = "verb_tamper"
    description = "Enumerate allowed HTTP methods and test HEAD bypass of auth-restricted endpoints"

    def run(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        base = url.rstrip("/")

        # Step 1: OPTIONS request on root to enumerate allowed methods
        findings.extend(self._check_options(base + "/"))

        # Step 2: Check for TRACE (reflects request back -- used for XST attacks)
        findings.extend(self._check_trace(base + "/"))

        # Step 3: Test HEAD bypass on common auth-restricted endpoints
        findings.extend(self._check_head_bypass(base))

        if not findings:
            findings.append(Finding(
                check="HTTP Verb Tampering",
                result="SECURE",
                severity="Info",
                evidence="No dangerous HTTP methods detected.",
            ))

        return findings

    def _check_options(self, url: str) -> list[Finding]:
        findings = []
        try:
            resp = requests.options(url, timeout=self.timeout, verify=False)
            allow_header = resp.headers.get("Allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
            if not allow_header:
                return findings

            allowed = {m.strip().upper() for m in allow_header.split(",")}
            dangerous_found = allowed & DANGEROUS_METHODS

            if dangerous_found:
                findings.append(Finding(
                    check="HTTP Verb Tampering: Dangerous Methods Allowed",
                    result="MISCONFIGURED",
                    severity="High",
                    evidence=f"OPTIONS response Allow: {allow_header}",
                    detail=(
                        f"Dangerous methods enabled: {', '.join(dangerous_found)}. "
                        "PUT allows file upload/overwrite on the server. "
                        "DELETE allows file deletion. "
                        "TRACE reflects request headers back (Cross-Site Tracing -- XST). "
                        "Fix (CBBH): restrict allowed methods in web server config; "
                        "for Apache: LimitExcept GET POST { deny from all }; "
                        "for Nginx: limit_except GET POST { deny all; }; "
                        "apply method restrictions consistently in BOTH server config AND application code."
                    ),
                    extra={"allowed_methods": list(allowed), "dangerous": list(dangerous_found)},
                ))
        except requests.RequestException:
            pass
        return findings

    def _check_trace(self, url: str) -> list[Finding]:
        findings = []
        try:
            resp = requests.request("TRACE", url, timeout=self.timeout, verify=False,
                                    headers={"X-KYA-Probe": "trace-test"})
            if resp.status_code == 200 and "X-KYA-Probe" in resp.text:
                findings.append(Finding(
                    check="HTTP TRACE Enabled (XST)",
                    result="VULNERABLE",
                    severity="Medium",
                    evidence=f"TRACE method responded with HTTP 200 and reflected request headers at {url}",
                    detail=(
                        "TRACE is enabled. Cross-Site Tracing (XST) allows an attacker to use "
                        "JavaScript to send a TRACE request and read reflected headers including "
                        "HttpOnly cookies (bypassing the HttpOnly flag via XST+XSS). "
                        "Fix: disable TRACE in web server config. "
                        "Apache: TraceEnable Off. Nginx: add 'if ($request_method = TRACE) { return 405; }'"
                    ),
                    raw_request=f"TRACE {url}",
                    raw_response=resp.text[:300],
                ))
        except requests.RequestException:
            pass
        return findings

    def _check_head_bypass(self, base: str) -> list[Finding]:
        findings = []
        for path in AUTH_ENDPOINTS:
            url = base + path
            try:
                # Normal GET -- expect 401/403 if protected
                get_resp = requests.get(url, timeout=self.timeout, verify=False,
                                        allow_redirects=False)
                if get_resp.status_code not in (401, 403):
                    continue

                # Try HEAD -- should also be 401/403 if server config is correct
                head_resp = requests.head(url, timeout=self.timeout, verify=False,
                                          allow_redirects=False)
                if head_resp.status_code == 200:
                    findings.append(Finding(
                        check="HTTP Verb Tamper: HEAD Auth Bypass",
                        result="VULNERABLE",
                        severity="High",
                        evidence=f"GET {url} → {get_resp.status_code}, HEAD {url} → {head_resp.status_code}",
                        detail=(
                            "Auth check is applied only to GET/POST, not HEAD. "
                            "Attacker sends HEAD request to bypass authentication on restricted endpoints. "
                            "Fix (CBBH): apply authentication checks to ALL HTTP methods, not just GET/POST; "
                            "use a global authentication middleware rather than per-method checks."
                        ),
                        raw_request=f"HEAD {url}",
                        raw_response=f"HTTP {head_resp.status_code}",
                    ))
            except requests.RequestException:
                continue
        return findings
