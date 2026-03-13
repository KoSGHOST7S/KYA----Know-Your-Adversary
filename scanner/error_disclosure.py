from __future__ import annotations

import re

import requests

from .base import BaseScanModule, Finding

PHP_ERROR_PATTERNS = [
    r"Fatal error:",
    r"Warning:.*on line \d+",
    r"Parse error:",
    r"Notice:.*on line \d+",
    r"Uncaught exception",
    r"Stack trace:",
    r"in /var/www",
    r"in /home/",
    r"in /usr/",
]

STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"at [A-Za-z]+\.[A-Za-z]+\(",
    r"Exception in thread",
    r"java\.lang\.",
    r"org\.springframework\.",
    r"Microsoft\.AspNet",
    r"System\.Web\.",
]

SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySQLSyntaxErrorException",
    r"ORA-\d{5}",
    r"PostgreSQL.*ERROR",
    r"sqlite3\.OperationalError",
    r"SQLSTATE\[",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Unclosed quotation mark",
]

PATH_DISCLOSURE_PATTERNS = [
    r"/var/www/html/",
    r"/home/\w+/",
    r"C:\\inetpub\\",
    r"C:\\Users\\",
    r"/usr/share/",
]


class ErrorDisclosureScanner(BaseScanModule):
    name = "error_disclosure"
    description = "Trigger error conditions to surface stack traces, PHP errors, SQL errors, and server banners"

    def run(self, url: str) -> list[Finding]:
        findings: list[Finding] = []

        # Trigger 404 with a unique path
        findings.extend(self._check_404(url))
        # Trigger 500 with malformed request
        findings.extend(self._check_malformed(url))
        # Check for info-disclosing headers (Server / X-Powered-By covered in headers module,
        # but we also check for ASP.NET version headers here)
        findings.extend(self._check_aspnet_headers(url))

        return findings

    def _check_404(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        probe_url = url.rstrip("/") + "/kya-probe-nonexistent-path-xzqq"
        try:
            resp = requests.get(probe_url, timeout=self.timeout, verify=False)
            body = resp.text
            findings.extend(self._scan_body(body, probe_url, "404 probe"))
        except requests.RequestException:
            pass
        return findings

    def _check_malformed(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = requests.post(
                url,
                data="INVALID_BODY_<>",
                headers={"Content-Type": "application/xml"},
                timeout=self.timeout,
                verify=False,
            )
            body = resp.text
            findings.extend(self._scan_body(body, url, "malformed POST probe"))
        except requests.RequestException:
            pass
        return findings

    def _check_aspnet_headers(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = requests.get(url, timeout=self.timeout, verify=False)
            if "X-AspNet-Version" in resp.headers:
                ver = resp.headers["X-AspNet-Version"]
                findings.append(Finding(
                    check="Info Disclosure Header: X-AspNet-Version",
                    result="MISCONFIGURED",
                    severity="Low",
                    evidence=f"X-AspNet-Version: {ver}",
                    detail="Exposes exact .NET version. Attackers look up CVEs for that version. "
                           "Fix: add <httpRuntime enableVersionHeader='false'/> in Web.config",
                    raw_request=f"GET {url}",
                    raw_response=str(dict(resp.headers))[:500],
                ))
            if "X-AspNetMvc-Version" in resp.headers:
                ver = resp.headers["X-AspNetMvc-Version"]
                findings.append(Finding(
                    check="Info Disclosure Header: X-AspNetMvc-Version",
                    result="MISCONFIGURED",
                    severity="Low",
                    evidence=f"X-AspNetMvc-Version: {ver}",
                    detail="Exposes ASP.NET MVC version. Fix: MvcHandler.DisableMvcResponseHeader = true",
                    raw_request=f"GET {url}",
                    raw_response=str(dict(resp.headers))[:500],
                ))
        except requests.RequestException:
            pass
        return findings

    def _scan_body(self, body: str, probe_url: str, probe_type: str) -> list[Finding]:
        findings: list[Finding] = []

        all_patterns = [
            (PHP_ERROR_PATTERNS, "PHP Error Disclosure", "High",
             "PHP errors reveal file paths, line numbers, and logic. "
             "Attackers use path disclosure to calibrate LFI traversal depth. "
             "Fix: set display_errors=Off and log_errors=On in php.ini"),
            (STACK_TRACE_PATTERNS, "Stack Trace Disclosure", "High",
             "Stack traces expose internal framework structure, class names, and file paths. "
             "Attackers use this to identify the framework version and known CVEs. "
             "Fix: implement a global exception handler that returns a generic error page."),
            (SQL_ERROR_PATTERNS, "SQL Error Disclosure", "High",
             "SQL errors confirm a database injection point and reveal the DB type/version. "
             "Attackers use this to tailor SQLi payloads. "
             "Fix: catch database exceptions and return a generic error; never expose raw SQL errors."),
            (PATH_DISCLOSURE_PATTERNS, "Path Disclosure", "Medium",
             "Absolute server paths in responses help attackers calibrate LFI/traversal payloads. "
             "Fix: suppress verbose errors and sanitize any user-facing output that might include paths."),
        ]

        for patterns, check_name, severity, detail in all_patterns:
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    snippet = body[max(0, match.start() - 50):match.end() + 100].strip()
                    findings.append(Finding(
                        check=check_name,
                        result="VULNERABLE",
                        severity=severity,
                        evidence=f"Pattern '{pattern}' matched in response to {probe_type}: ...{snippet}...",
                        detail=detail,
                        raw_request=f"GET/POST {probe_url}",
                        raw_response=body[:500],
                    ))
                    break  # one finding per category is enough

        return findings
