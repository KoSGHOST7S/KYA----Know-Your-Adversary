from __future__ import annotations

import requests

from .base import BaseScanModule, Finding

REQUIRED_HEADERS = [
    (
        "Content-Security-Policy",
        "High",
        "Missing CSP allows XSS payloads to execute without restriction. "
        "An attacker can inject scripts via reflected/stored XSS and steal session cookies. "
        "Fix: add Content-Security-Policy: default-src 'self'",
    ),
    (
        "Strict-Transport-Security",
        "Medium",
        "Missing HSTS allows SSL stripping attacks (e.g. sslstrip). "
        "Attacker on the network can downgrade HTTPS to HTTP and intercept credentials. "
        "Fix: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    (
        "X-Frame-Options",
        "Medium",
        "Missing X-Frame-Options enables clickjacking. "
        "Attacker embeds the page in an invisible iframe and tricks users into clicking hidden elements. "
        "Fix: X-Frame-Options: DENY or SAMEORIGIN",
    ),
    (
        "X-Content-Type-Options",
        "Medium",
        "Missing X-Content-Type-Options: nosniff enables MIME-type sniffing. "
        "Combined with a file upload vulnerability, an attacker can upload a file with a safe MIME type "
        "that the browser executes as HTML/JS. Fix: X-Content-Type-Options: nosniff",
    ),
    (
        "Referrer-Policy",
        "Low",
        "Missing Referrer-Policy leaks the full URL in the Referer header to third parties. "
        "Can expose tokens or sensitive paths in URLs. "
        "Fix: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    (
        "Permissions-Policy",
        "Low",
        "Missing Permissions-Policy leaves browser features (camera, geolocation, microphone) unrestricted. "
        "Fix: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    ),
]

INSECURE_HEADER_PATTERNS = {
    "Server": "Server banner discloses software and version (e.g. Apache/2.4.49). "
              "Attackers use this to look up known CVEs for that exact version. "
              "Fix: configure ServerTokens Prod in Apache or server_tokens off in Nginx.",
    "X-Powered-By": "X-Powered-By discloses the backend language/framework and version. "
                    "Fix: remove this header in application config or web server.",
}


class HeadersScanner(BaseScanModule):
    name = "headers"
    description = "Check for missing security headers and information-disclosing response headers"

    def run(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = requests.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
        except requests.RequestException as exc:
            findings.append(Finding(
                check="Headers",
                result="INFO",
                severity="Info",
                evidence=f"Could not fetch {url}: {exc}",
            ))
            return findings

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header_name, severity, detail in REQUIRED_HEADERS:
            if header_name.lower() not in headers_lower:
                findings.append(Finding(
                    check=f"Missing Header: {header_name}",
                    result="MISCONFIGURED",
                    severity=severity,
                    evidence=f"{header_name} not present in response from {url}",
                    detail=detail,
                    raw_request=f"GET {url}",
                    raw_response=str(dict(resp.headers))[:500],
                ))
            else:
                findings.append(Finding(
                    check=f"Missing Header: {header_name}",
                    result="SECURE",
                    severity="Info",
                    evidence=f"{header_name}: {headers_lower[header_name.lower()]}",
                ))

        for header_name, detail in INSECURE_HEADER_PATTERNS.items():
            if header_name.lower() in headers_lower:
                val = headers_lower[header_name.lower()]
                findings.append(Finding(
                    check=f"Info Disclosure Header: {header_name}",
                    result="MISCONFIGURED",
                    severity="Low",
                    evidence=f"{header_name}: {val}",
                    detail=detail,
                    raw_request=f"GET {url}",
                    raw_response=str(dict(resp.headers))[:500],
                ))

        return findings
