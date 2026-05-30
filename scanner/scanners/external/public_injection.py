"""
scanners/external/public_injection.py
Deteksi injection vulnerability pada form publik OJS (unauthenticated).

Test XSS dan SQL injection pada endpoint yang dapat diakses tanpa login:
login form, registrasi, pencarian, dan halaman kontak.
"""

import re
import requests
from scanners.base import ScannerModule, Finding


# Payload XSS yang digunakan untuk cek reflection
XSS_PAYLOADS = [
    '<script>alert("OJS-XSS-TEST")</script>',
    '"><img src=x onerror=alert(1)>',
    "'><svg onload=alert(1)>",
]
XSS_MARKER = "OJS-XSS-TEST"

# Payload SQLi error-based
SQLI_PAYLOADS = [
    ("'", ["SQL syntax", "mysql_fetch", "ORA-01756", "Unclosed quotation", "pg_query()"]),
    ('"', ["SQL syntax", "mysql_fetch", "syntax error"]),
    ("1 OR 1=1--", ["SQL syntax", "mysql_fetch"]),
]

# Path traversal payload
LFI_PAYLOADS = [
    ("../../../etc/passwd", ["root:x:0:0", "daemon:", "nobody:"]),
    ("..%2F..%2F..%2Fetc%2Fpasswd", ["root:x:0:0"]),
]


class PublicInjectionScanner(ScannerModule):
    name = "public_injection"

    REQUEST_TIMEOUT = 10

    def run(self, **kwargs) -> dict:
        findings = []

        findings.extend(self._check_login_form_injection())
        findings.extend(self._check_registration_form_xss())
        findings.extend(self._check_search_injection())
        findings.extend(self._check_open_redirect())

        return self.result(findings)

    # ── Checks ─────────────────────────────────────────────────

    def _check_login_form_injection(self) -> list[Finding]:
        """
        Test injection pada form login OJS.
        Uji SQLi dan XSS reflection di field username.
        """
        findings = []
        login_url = f"{self.target_url}/index.php/index/login/signIn"

        # Ambil CSRF token dulu
        csrf_token = self._get_csrf_token(f"{self.target_url}/index.php/index/login")

        # Test SQLi di field username
        for payload, error_patterns in SQLI_PAYLOADS:
            try:
                form_data = {
                    "username": payload,
                    "password": "wrongpassword",
                }
                if csrf_token:
                    form_data["csrfToken"] = csrf_token

                resp = requests.post(
                    login_url,
                    data=form_data,
                    timeout=self.REQUEST_TIMEOUT,
                    allow_redirects=True,
                )

                for error in error_patterns:
                    if re.search(re.escape(error), resp.text, re.IGNORECASE):
                        findings.append(Finding(
                            title="SQL Injection di Login Form (Error-Based)",
                            severity="critical",
                            description=(
                                "Field username di form login OJS mengembalikan error SQL database "
                                "saat diinput dengan karakter khusus. Ini mengindikasikan SQL injection "
                                "yang dapat digunakan untuk bypass autentikasi atau dump data."
                            ),
                            evidence=f"Payload: {payload!r}\nError: '{error}'\nURL: {login_url}",
                            module=self.name,
                            cve="CVE-2019-17648",
                            remediation=(
                                "Gunakan prepared statements untuk query autentikasi. "
                                "Jangan tampilkan error database ke user. "
                                "Update OJS ke versi terbaru."
                            ),
                            url=login_url,
                            extra={"cwe_id": "CWE-89", "payload": payload},
                        ))
                        return findings

            except requests.RequestException:
                continue

        # Test XSS reflection di error message login
        for payload in XSS_PAYLOADS[:2]:
            try:
                form_data = {
                    "username": payload,
                    "password": "wrongpassword",
                }
                if csrf_token:
                    form_data["csrfToken"] = csrf_token

                resp = requests.post(
                    login_url,
                    data=form_data,
                    timeout=self.REQUEST_TIMEOUT,
                    allow_redirects=True,
                )

                # Cek apakah payload muncul tanpa encoding di response
                if XSS_MARKER in resp.text and payload in resp.text:
                    findings.append(Finding(
                        title="Reflected XSS di Login Form",
                        severity="medium",
                        description=(
                            "Input dari field username di-reflect kembali ke halaman "
                            "tanpa HTML encoding yang memadai. Attacker dapat membuat "
                            "link khusus yang saat diklik akan mengeksekusi script di browser korban."
                        ),
                        evidence=f"Payload '{payload[:50]}...' ditemukan unencoded di response",
                        module=self.name,
                        cve="CVE-2022-24181",
                        remediation=(
                            "Escape semua output yang berasal dari input user menggunakan "
                            "htmlspecialchars() atau escaping yang disediakan framework OJS."
                        ),
                        url=login_url,
                        extra={"cwe_id": "CWE-79", "payload": payload},
                    ))
                    break

            except requests.RequestException:
                continue

        return findings

    def _check_registration_form_xss(self) -> list[Finding]:
        """
        Test XSS pada form registrasi OJS.
        Field nama depan/belakang sering tidak di-sanitize dengan baik.
        """
        findings = []
        register_page_url = f"{self.target_url}/index.php/index/user/register"
        register_url = f"{self.target_url}/index.php/index/user/register"

        csrf_token = self._get_csrf_token(register_page_url)

        for payload in XSS_PAYLOADS[:1]:
            try:
                form_data = {
                    "firstName": payload,
                    "lastName": "TestUser",
                    "username": f"test_xss_{hash(payload) % 10000}",
                    "email": f"test{hash(payload) % 10000}@example.com",
                    "password": "TestPassword123!",
                    "password2": "TestPassword123!",
                    "privacyConsent": "1",
                }
                if csrf_token:
                    form_data["csrfToken"] = csrf_token

                resp = requests.post(
                    register_url,
                    data=form_data,
                    timeout=self.REQUEST_TIMEOUT,
                    allow_redirects=True,
                )

                if XSS_MARKER in resp.text and payload in resp.text:
                    findings.append(Finding(
                        title="Reflected XSS di Form Registrasi (Field Nama)",
                        severity="medium",
                        description=(
                            "Field nama di form registrasi OJS ter-reflect tanpa HTML encoding. "
                            "Payload XSS terlihat di response setelah submit. "
                            "Ini berpotensi menjadi Stored XSS jika nama user ditampilkan di halaman lain."
                        ),
                        evidence=f"Payload XSS ditemukan unencoded di response registrasi",
                        module=self.name,
                        remediation=(
                            "Escape semua output nama user menggunakan htmlspecialchars(). "
                            "Implementasi Content Security Policy (CSP)."
                        ),
                        url=register_url,
                        extra={"cwe_id": "CWE-79"},
                    ))
                    break

            except requests.RequestException:
                continue

        return findings

    def _check_search_injection(self) -> list[Finding]:
        """
        Test injection pada endpoint pencarian OJS.
        Endpoint search sering menjadi target SQLi dan XSS.
        """
        findings = []
        search_base = f"{self.target_url}/index.php/index/search/search"

        # Test XSS di parameter query
        for payload in XSS_PAYLOADS[:2]:
            url = f"{search_base}?query={requests.utils.quote(payload)}"
            try:
                resp = requests.get(url, timeout=self.REQUEST_TIMEOUT)

                if XSS_MARKER in resp.text and payload in resp.text:
                    findings.append(Finding(
                        title="Reflected XSS di Endpoint Pencarian",
                        severity="medium",
                        description=(
                            "Parameter 'query' di endpoint pencarian OJS ter-reflect "
                            "tanpa HTML encoding yang memadai. Dapat dimanfaatkan untuk "
                            "serangan XSS berbasis URL yang dikirim ke korban."
                        ),
                        evidence=f"GET {url}\nPayload ditemukan unencoded di response",
                        module=self.name,
                        remediation=(
                            "Escape parameter query sebelum ditampilkan di halaman pencarian."
                        ),
                        url=url,
                        extra={"cwe_id": "CWE-79"},
                    ))
                    break

            except requests.RequestException:
                continue

        # Test SQLi di parameter query
        for payload, error_patterns in SQLI_PAYLOADS[:2]:
            url = f"{search_base}?query={requests.utils.quote(payload)}"
            try:
                resp = requests.get(url, timeout=self.REQUEST_TIMEOUT)

                for error in error_patterns:
                    if re.search(re.escape(error), resp.text, re.IGNORECASE):
                        findings.append(Finding(
                            title="SQL Injection di Endpoint Pencarian",
                            severity="high",
                            description=(
                                "Parameter 'query' di halaman pencarian OJS menghasilkan "
                                "error SQL database. Rentan terhadap SQL injection yang "
                                "dapat digunakan untuk ekstrak data dari database."
                            ),
                            evidence=f"GET {url}\nError: '{error}'",
                            module=self.name,
                            remediation=(
                                "Gunakan prepared statements untuk query pencarian. "
                                "Sanitasi input query sebelum digunakan dalam SQL."
                            ),
                            url=url,
                            extra={"cwe_id": "CWE-89", "payload": payload},
                        ))
                        return findings

            except requests.RequestException:
                continue

        return findings

    def _check_open_redirect(self) -> list[Finding]:
        """
        Test open redirect pada parameter source/returnUrl di login dan logout.
        """
        findings = []
        redirect_tests = [
            (f"{self.target_url}/index.php/index/login", {"source": "https://evil.example.com"}),
            (f"{self.target_url}/index.php/index/login", {"returnUrl": "https://evil.example.com"}),
            (f"{self.target_url}/index.php/index/login", {"source": "//evil.example.com"}),
        ]

        for url, params in redirect_tests:
            try:
                resp = requests.get(
                    url,
                    params=params,
                    timeout=self.REQUEST_TIMEOUT,
                    allow_redirects=False,  # Jangan follow redirect!
                )

                location = resp.headers.get("Location", "")
                if resp.status_code in (301, 302, 303, 307, 308):
                    if "evil.example.com" in location:
                        param_name = list(params.keys())[0]
                        findings.append(Finding(
                            title=f"Open Redirect via Parameter '{param_name}'",
                            severity="medium",
                            description=(
                                f"Parameter '{param_name}' di halaman login OJS digunakan "
                                f"langsung untuk redirect tanpa validasi domain. "
                                "Attacker dapat membuat link login yang redirect ke situs phishing "
                                "setelah user memasukkan kredensial mereka."
                            ),
                            evidence=(
                                f"GET {url}?{param_name}=https://evil.example.com "
                                f"→ HTTP {resp.status_code} Location: {location}"
                            ),
                            module=self.name,
                            remediation=(
                                "Validasi parameter redirect — hanya izinkan redirect ke "
                                "domain yang sama (same-origin). Gunakan whitelist domain "
                                "yang diizinkan untuk redirect."
                            ),
                            url=url,
                            extra={"cwe_id": "CWE-601", "redirect_param": param_name},
                        ))
                        return findings  # Satu temuan cukup

            except requests.RequestException:
                continue

        return findings

    def _get_csrf_token(self, url: str) -> str | None:
        """Ambil CSRF token dari halaman HTML."""
        try:
            resp = requests.get(url, timeout=self.REQUEST_TIMEOUT)
            patterns = [
                r'<input[^>]+name=["\']csrfToken["\'][^>]+value=["\']([^"\']+)["\']',
                r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']csrfToken["\']',
            ]
            for pattern in patterns:
                match = re.search(pattern, resp.text, re.IGNORECASE)
                if match:
                    return match.group(1)
        except requests.RequestException:
            pass
        return None
