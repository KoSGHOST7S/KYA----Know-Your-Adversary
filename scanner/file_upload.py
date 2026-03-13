from __future__ import annotations

import io

import requests
from bs4 import BeautifulSoup

from .base import BaseScanModule, Finding

# Extensions that bypass common blacklists (CBBH Module 11: Blacklist Filters)
BLACKLIST_BYPASS_EXTENSIONS = [
    ".php5", ".php7", ".phtml", ".phar", ".shtml",
    ".asp", ".aspx", ".cer", ".pHp", ".PhP",
]

# Common upload directory paths to probe
UPLOAD_DIRS = [
    "/uploads/", "/upload/", "/files/", "/file/",
    "/media/", "/images/", "/img/", "/assets/uploads/",
    "/content/uploads/", "/wp-content/uploads/",
]

# Framework fingerprinting paths (CBBH 11: Identifying Web Framework)
FRAMEWORK_PROBES = [
    ("/index.php", "PHP"),
    ("/index.asp", "ASP"),
    ("/index.aspx", "ASP.NET"),
    ("/index.jsp", "JSP"),
]

WEBSHELL_MARKER = "KYA-PROBE-OK"
WEBSHELL_CONTENT = f'<?php echo "{WEBSHELL_MARKER}"; ?>'


class FileUploadScanner(BaseScanModule):
    name = "file_upload"
    description = "Detect file upload forms, fingerprint framework, test blacklist bypass extensions"

    def run(self, url: str) -> list[Finding]:
        findings: list[Finding] = []

        # Step 1: Fingerprint the framework
        framework = self._fingerprint_framework(url)
        if framework:
            findings.append(Finding(
                check="Framework Fingerprint",
                result="INFO",
                severity="Info",
                evidence=f"Framework detected: {framework}",
                detail="Framework identified. Confirms which shell extension to use for file upload attacks.",
            ))

        # Step 2: Detect upload forms
        upload_forms = self._find_upload_forms(url)
        if not upload_forms:
            findings.append(Finding(
                check="File Upload",
                result="INFO",
                severity="Info",
                evidence="No file upload forms detected on the target page.",
            ))
        else:
            findings.append(Finding(
                check="File Upload Form Detected",
                result="INFO",
                severity="Info",
                evidence=f"Found {len(upload_forms)} file upload form(s) on {url}",
                detail="File upload forms present. Testing extension blacklist bypass and upload directory exposure.",
            ))

            # Step 3: Test extension bypass for each form
            for form in upload_forms:
                ext_finding = self._test_extension_bypass(url, form, framework)
                if ext_finding:
                    findings.append(ext_finding)

        # Step 4: Check if upload directories are web-accessible
        findings.extend(self._check_upload_dirs(url))

        return findings

    def _fingerprint_framework(self, url: str) -> str | None:
        base = url.rstrip("/")
        for path, name in FRAMEWORK_PROBES:
            try:
                resp = requests.get(base + path, timeout=self.timeout, verify=False,
                                    allow_redirects=False)
                if resp.status_code in (200, 301, 302, 403):
                    return name
            except requests.RequestException:
                continue
        return None

    def _find_upload_forms(self, url: str) -> list[dict]:
        forms = []
        try:
            resp = requests.get(url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(resp.text, "html.parser")
            for form in soup.find_all("form"):
                file_inputs = form.find_all("input", {"type": "file"})
                if file_inputs:
                    action = form.get("action", url)
                    method = form.get("method", "post").lower()
                    forms.append({
                        "action": action if action.startswith("http") else url.rstrip("/") + "/" + action.lstrip("/"),
                        "method": method,
                        "file_inputs": [inp.get("name", "file") for inp in file_inputs],
                    })
        except requests.RequestException:
            pass
        return forms

    def _test_extension_bypass(self, base_url: str, form: dict, framework: str | None) -> Finding | None:
        action = form["action"]
        file_field = form["file_inputs"][0] if form["file_inputs"] else "file"

        for ext in BLACKLIST_BYPASS_EXTENSIONS:
            # Skip non-relevant extensions based on framework
            if framework == "PHP" and ext in (".asp", ".aspx", ".cer"):
                continue
            if framework in ("ASP", "ASP.NET") and ext in (".php5", ".php7", ".phtml", ".phar"):
                continue

            filename = f"kya_test{ext}"
            try:
                files = {file_field: (filename, io.BytesIO(WEBSHELL_CONTENT.encode()), "image/jpeg")}
                resp = requests.post(action, files=files, timeout=self.timeout, verify=False,
                                     allow_redirects=True)
                if resp.status_code in (200, 201):
                    # Check if a path to the uploaded file is in the response
                    if any(d.strip("/") in resp.text for d in UPLOAD_DIRS) or filename in resp.text:
                        return Finding(
                            check="File Upload: Blacklist Bypass",
                            result="VULNERABLE",
                            severity="Critical",
                            evidence=f"Extension '{ext}' accepted by upload form at {action}",
                            detail=(
                                f"Upload form accepted '{ext}' -- a potentially executable extension. "
                                "Attacker uploads a webshell, navigates to its URL, and achieves RCE. "
                                "Fix (CBBH): use a whitelist (only jpg/png/gif); validate Content-Type AND magic bytes; "
                                "rename uploaded files randomly; serve files via download.php not direct path; "
                                "disable dangerous PHP functions (exec, system) in php.ini; "
                                "ensure X-Content-Type-Options: nosniff is set."
                            ),
                            raw_request=f"POST {action} [{filename}]",
                            raw_response=resp.text[:400],
                        )
            except requests.RequestException:
                continue
        return None

    def _check_upload_dirs(self, url: str) -> list[Finding]:
        findings = []
        base = url.rstrip("/")
        for path in UPLOAD_DIRS:
            try:
                resp = requests.get(base + path, timeout=self.timeout, verify=False,
                                    allow_redirects=True)
                if resp.status_code == 200 and len(resp.text) > 50:
                    findings.append(Finding(
                        check="Upload Directory Exposed",
                        result="MISCONFIGURED",
                        severity="High",
                        evidence=f"Upload directory is web-accessible: {base + path} (HTTP {resp.status_code})",
                        detail=(
                            "Upload directory is accessible. If an attacker uploads a webshell, they can "
                            "directly browse to it and execute commands. "
                            "Fix: block direct access to the uploads directory (return 403 in .htaccess or Nginx); "
                            "serve files only through a controlled download script; "
                            "randomize stored filenames."
                        ),
                        raw_request=f"GET {base + path}",
                        raw_response=resp.text[:300],
                    ))
            except requests.RequestException:
                continue
        return findings
