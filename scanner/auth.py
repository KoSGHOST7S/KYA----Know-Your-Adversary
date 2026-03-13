from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter

import requests
from bs4 import BeautifulSoup

from .base import BaseScanModule, Finding

# Default credentials to test (CBBH 14: Default Credentials)
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "password123"),
    ("root", "root"),
    ("root", "toor"),
    ("guest", "guest"),
    ("user", "user"),
    ("test", "test"),
    ("administrator", "administrator"),
    ("admin", ""),
]

# Patterns that indicate a successful login
LOGIN_SUCCESS_PATTERNS = [
    r"dashboard",
    r"welcome",
    r"logout",
    r"sign.?out",
    r"profile",
    r"my.?account",
]

# Patterns that indicate a failed login
LOGIN_FAIL_PATTERNS = [
    r"invalid",
    r"incorrect",
    r"wrong",
    r"failed",
    r"error",
    r"unauthorized",
    r"try again",
]

# Patterns for lockout detection
LOCKOUT_PATTERNS = [
    r"account.?locked",
    r"too many.?attempt",
    r"temporarily.?disabled",
    r"captcha",
    r"rate.?limit",
]

# Predictable session token patterns (CBBH 14: Attacking Session Tokens)
# e.g. base64 of "user=htb-stdnt;role=user"
ROLE_PATTERNS = [
    r"role=",
    r"admin=",
    r"is_admin=",
    r"user=",
    r"type=",
    r"level=",
]


class AuthScanner(BaseScanModule):
    name = "auth"
    description = "Test default credentials, session lockout, and session token entropy/predictability"

    def run(self, url: str) -> list[Finding]:
        findings: list[Finding] = []

        # Step 1: Find login forms
        login_forms = self._find_login_forms(url)

        if not login_forms:
            findings.append(Finding(
                check="Auth: Login Form",
                result="INFO",
                severity="Info",
                evidence="No login form detected on the target page.",
                detail="Try /login, /admin, /wp-login.php, /signin manually.",
            ))
        else:
            # Step 2: Test default credentials
            for form in login_forms:
                cred_findings = self._test_default_creds(url, form)
                findings.extend(cred_findings)

                # Step 3: Test lockout
                lockout_finding = self._test_lockout(url, form)
                if lockout_finding:
                    findings.append(lockout_finding)

        # Step 4: Analyze session cookies
        findings.extend(self._analyze_session_cookies(url))

        return findings

    def _find_login_forms(self, url: str) -> list[dict]:
        forms = []
        # Probe common login paths
        login_paths = ["", "/login", "/signin", "/admin", "/wp-login.php",
                       "/user/login", "/account/login", "/auth/login"]
        base = url.rstrip("/")

        for path in login_paths:
            try:
                resp = requests.get(base + path, timeout=self.timeout, verify=False,
                                    allow_redirects=True)
                soup = BeautifulSoup(resp.text, "html.parser")
                for form in soup.find_all("form"):
                    pw_inputs = form.find_all("input", {"type": "password"})
                    if pw_inputs:
                        user_inputs = (
                            form.find_all("input", {"type": "text"}) +
                            form.find_all("input", {"type": "email"}) +
                            form.find_all("input", {"name": re.compile(r"user|email|login", re.I)})
                        )
                        action = form.get("action", base + path)
                        full_action = action if action.startswith("http") else base + "/" + action.lstrip("/")
                        forms.append({
                            "action": full_action,
                            "method": form.get("method", "post").lower(),
                            "user_field": user_inputs[0].get("name", "username") if user_inputs else "username",
                            "pass_field": pw_inputs[0].get("name", "password"),
                            "page": base + path,
                        })
            except requests.RequestException:
                continue

        return forms

    def _test_default_creds(self, url: str, form: dict) -> list[Finding]:
        findings = []
        for username, password in DEFAULT_CREDS:
            try:
                data = {
                    form["user_field"]: username,
                    form["pass_field"]: password,
                }
                resp = requests.post(
                    form["action"], data=data,
                    timeout=self.timeout, verify=False,
                    allow_redirects=True,
                )
                body = resp.text.lower()

                # Check for lockout first
                if any(re.search(p, body) for p in LOCKOUT_PATTERNS):
                    findings.append(Finding(
                        check="Auth: Account Lockout Triggered",
                        result="INFO",
                        severity="Info",
                        evidence=f"Lockout/rate-limit detected after testing credentials at {form['action']}",
                    ))
                    break

                # Check for success indicators
                if (resp.status_code in (200,) and
                        any(re.search(p, body) for p in LOGIN_SUCCESS_PATTERNS) and
                        not any(re.search(p, body) for p in LOGIN_FAIL_PATTERNS)):
                    findings.append(Finding(
                        check="Auth: Default Credentials",
                        result="VULNERABLE",
                        severity="Critical",
                        evidence=f"Login succeeded with {username}:{password} at {form['action']}",
                        detail=(
                            "Default credentials work. Attacker gains authenticated access immediately. "
                            "Fix: change default credentials on deployment; enforce strong password policy; "
                            "implement account lockout after 5 failed attempts; "
                            "consider MFA for admin accounts."
                        ),
                        raw_request=f"POST {form['action']} [{username}:{password}]",
                        raw_response=resp.text[:300],
                    ))
                    return findings  # Stop after first success

            except requests.RequestException:
                continue

        if not findings:
            findings.append(Finding(
                check="Auth: Default Credentials",
                result="SECURE",
                severity="Info",
                evidence=f"No default credentials worked at {form['action']}",
            ))
        return findings

    def _test_lockout(self, url: str, form: dict) -> Finding | None:
        lockout_detected = False
        for i in range(6):
            try:
                data = {
                    form["user_field"]: "admin",
                    form["pass_field"]: f"wrong_password_{i}_kya",
                }
                resp = requests.post(
                    form["action"], data=data,
                    timeout=self.timeout, verify=False,
                    allow_redirects=True,
                )
                if resp.status_code == 429:
                    lockout_detected = True
                    break
                body = resp.text.lower()
                if any(re.search(p, body) for p in LOCKOUT_PATTERNS):
                    lockout_detected = True
                    break
            except requests.RequestException:
                break

        if not lockout_detected:
            return Finding(
                check="Auth: No Brute-Force Protection",
                result="MISCONFIGURED",
                severity="High",
                evidence=f"No lockout or rate-limiting detected after 6 failed attempts at {form['action']}",
                detail=(
                    "No account lockout or rate limiting. Attacker can brute-force passwords indefinitely. "
                    "Fix (CBBH): implement account lockout after 5 failed attempts; "
                    "use exponential backoff; consider CAPTCHA after 3 failures; "
                    "return HTTP 429 with Retry-After header for rate limiting."
                ),
            )
        return None

    def _analyze_session_cookies(self, url: str) -> list[Finding]:
        findings = []
        try:
            resp = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            for cookie in resp.cookies:
                name = cookie.name
                value = cookie.value or ""

                # Check security flags
                missing_flags = []
                if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie).lower():
                    missing_flags.append("HttpOnly")
                if not cookie.secure:
                    missing_flags.append("Secure")

                if missing_flags:
                    findings.append(Finding(
                        check=f"Session Cookie Flags: {name}",
                        result="MISCONFIGURED",
                        severity="Medium",
                        evidence=f"Cookie '{name}' missing flags: {', '.join(missing_flags)}",
                        detail=(
                            "Missing HttpOnly allows JavaScript to read the cookie (XSS → session hijack). "
                            "Missing Secure allows transmission over HTTP (SSL stripping → session theft). "
                            "Fix: set HttpOnly and Secure flags on all session cookies; "
                            "add SameSite=Strict to prevent CSRF."
                        ),
                    ))

                # Check for predictable/encodable session tokens (CBBH 14: Attacking Session Tokens)
                decoded = self._decode_token(value)
                if decoded:
                    for pattern in ROLE_PATTERNS:
                        if re.search(pattern, decoded, re.IGNORECASE):
                            findings.append(Finding(
                                check=f"Predictable Session Token: {name}",
                                result="VULNERABLE",
                                severity="Critical",
                                evidence=f"Cookie '{name}' decodes to: {decoded}",
                                detail=(
                                    "Session token contains user-controlled role/privilege data in a predictable encoding. "
                                    "Attacker decodes the token, modifies 'role=user' to 'role=admin', re-encodes, "
                                    "and replaces the cookie to gain admin access. "
                                    "Fix: never store role/privilege data in client-side tokens; "
                                    "use opaque server-side session IDs with server-stored state; "
                                    "sign tokens with HMAC if client-side data is unavoidable."
                                ),
                                raw_response=f"Cookie: {name}={value}",
                            ))
                            break

                # Check token entropy
                entropy = self._shannon_entropy(value)
                if len(value) < 16 or entropy < 3.0:
                    findings.append(Finding(
                        check=f"Low-Entropy Session Token: {name}",
                        result="MISCONFIGURED",
                        severity="High",
                        evidence=f"Cookie '{name}' has low entropy (length={len(value)}, entropy={entropy:.2f})",
                        detail=(
                            "Short or low-entropy session token is brute-forceable. "
                            "Attacker iterates token values to hijack other users' sessions. "
                            "Fix: use a cryptographically secure random generator; "
                            "session tokens should be at least 128 bits (32 hex chars) of entropy."
                        ),
                    ))

        except requests.RequestException:
            pass
        return findings

    @staticmethod
    def _decode_token(value: str) -> str | None:
        """Try base64 and hex decoding to detect role-containing session tokens."""
        # Base64
        try:
            padding = "=" * (4 - len(value) % 4)
            decoded = base64.b64decode(value + padding).decode("utf-8", errors="ignore")
            if any(c.isprintable() for c in decoded) and len(decoded) > 3:
                return decoded
        except Exception:
            pass
        # Hex
        try:
            if re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) % 2 == 0:
                decoded = binascii.unhexlify(value).decode("utf-8", errors="ignore")
                if any(c.isprintable() for c in decoded) and len(decoded) > 3:
                    return decoded
        except Exception:
            pass
        return None

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())
