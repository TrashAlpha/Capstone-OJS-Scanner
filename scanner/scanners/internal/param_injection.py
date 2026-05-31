"""
scanners/internal/param_injection.py
Deteksi injection vulnerability pada parameter yang memerlukan autentikasi.

Uji SQL injection, Stored XSS, dan SSTI pada endpoint OJS yang
hanya dapat diakses setelah login sebagai admin atau editor.
"""

import re
import requests
from scanners.base import ScannerModule, Finding


# Payload SQLi error-based yang umum
SQLI_PAYLOADS = [
    ("'", ["SQL syntax", "mysql_fetch", "ORA-", "syntax error", "Unclosed quotation"]),
    ("1 OR 1=1--", ["SQL syntax", "mysql_fetch", "Warning:"]),
    ("' OR '1'='1", ["SQL syntax", "mysql_fetch"]),
]

# Payload SSTI untuk berbagai template engine
SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),      # Jinja2, Twig
    ("${7*7}", "49"),       # Freemarker, Spring EL
    ("<%= 7*7 %>", "49"),   # ERB
]

# Payload XSS sederhana untuk stored XSS
XSS_PAYLOAD = "<script>window.__xss_test_ojs=1</script>"
XSS_MARKER = "__xss_test_ojs"


class ParamInjectionScanner(ScannerModule):
    name = "param_injection"

    REQUEST_TIMEOUT = 15

    def run(self, **kwargs) -> dict:
        findings = []

        if not self.session:
            findings.append(Finding(
                title="Internal Scanner: Session Tidak Tersedia",
                severity="info",
                description="ParamInjectionScanner memerlukan sesi terotentikasi.",
                evidence="session=None",
                module=self.name,
            ))
            return self.result(findings)

        findings.extend(self._check_admin_sqli())
        findings.extend(self._check_stored_xss())
        findings.extend(self._check_ssti_email_template())
        findings.extend(self._check_crlf_injection())

        return self.result(findings)

    # ── Checks ─────────────────────────────────────────────────

    def _check_admin_sqli(self) -> list[Finding]:
        """Test SQL injection di endpoint admin yang memerlukan autentikasi."""
        findings = []
        test_endpoints = [
            f"{self.target_url}/index.php/index/admin/users",
            f"{self.target_url}/index.php/index/management/users",
        ]

        for base_url in test_endpoints:
            for payload, error_patterns in SQLI_PAYLOADS:
                url = f"{base_url}?search={requests.utils.quote(payload)}"
                try:
                    resp = self.session.get(url, timeout=self.REQUEST_TIMEOUT)
                    if resp.status_code not in (200, 500):
                        continue

                    for error in error_patterns:
                        if re.search(re.escape(error), resp.text, re.IGNORECASE):
                            findings.append(Finding(
                                title="SQL Injection di Endpoint Admin (Error-Based)",
                                severity="critical",
                                description=(
                                    f"Parameter 'search' di halaman manajemen user OJS rentan "
                                    f"terhadap SQL injection. Error database terlihat di response, "
                                    f"yang menunjukkan query SQL tidak di-sanitize dengan benar. "
                                    f"Dapat digunakan untuk dump database atau bypass autentikasi."
                                ),
                                evidence=f"Payload: {payload!r}\nError terdeteksi: '{error}'\nURL: {url}",
                                module=self.name,
                                cve="CVE-2019-17648",
                                remediation=(
                                    "Gunakan prepared statements / parameterized queries untuk semua "
                                    "query database. Update OJS ke versi terbaru. "
                                    "Sanitasi semua input user sebelum dimasukkan ke query SQL."
                                ),
                                url=url,
                                extra={"cwe_id": "CWE-89", "payload": payload},
                            ))
                            return findings  # Stop setelah temuan pertama

                except requests.RequestException:
                    continue

        return findings

    def _check_stored_xss(self) -> list[Finding]:
        """
        Test Stored XSS di journal settings — title journal.
        Jika berhasil, XSS akan muncul di halaman utama OJS.
        """
        findings = []
        settings_url = f"{self.target_url}/index.php/index/management/settings/context"

        # Step 1: Ambil form settings + CSRF token
        try:
            resp = self.session.get(settings_url, timeout=self.REQUEST_TIMEOUT)
            if resp.status_code != 200:
                return findings
        except requests.RequestException:
            return findings

        csrf_token = self._extract_csrf(resp.text)

        # Step 2: Submit judul dengan XSS payload
        try:
            post_data = {
                "name[en]": XSS_PAYLOAD,
                "csrfToken": csrf_token or "",
            }
            post_resp = self.session.post(
                settings_url,
                data=post_data,
                timeout=self.REQUEST_TIMEOUT,
                allow_redirects=True,
            )

            # Step 3: Cek apakah payload muncul di homepage
            home_resp = self.session.get(
                self.target_url,
                timeout=self.REQUEST_TIMEOUT,
            )

            if XSS_MARKER in home_resp.text:
                findings.append(Finding(
                    title="Stored XSS di Journal Title (Admin)",
                    severity="high",
                    description=(
                        "Nama/judul journal yang disubmit melalui admin settings "
                        "tidak di-sanitize dan ter-render sebagai HTML di halaman publik. "
                        "Setiap pengunjung website akan terkena XSS ini (stored/persistent XSS)."
                    ),
                    evidence=(
                        f"Payload '{XSS_PAYLOAD}' disubmit ke journal title, "
                        f"kemudian ditemukan di halaman utama tanpa encoding."
                    ),
                    module=self.name,
                    cve="CVE-2024-24511",
                    remediation=(
                        "Sanitasi semua input teks yang bisa mengandung HTML sebelum disimpan. "
                        "Gunakan htmlspecialchars() atau escaping framework OJS yang tersedia. "
                        "Update ke OJS versi terbaru yang sudah fix CVE-2024-24511."
                    ),
                    url=settings_url,
                    extra={"cwe_id": "CWE-79"},
                ))

        except requests.RequestException:
            pass

        return findings

    def _check_ssti_email_template(self) -> list[Finding]:
        """
        Test Server-Side Template Injection di email template admin.
        OJS menggunakan Smarty template engine untuk email notifications.
        """
        findings = []
        template_url = f"{self.target_url}/index.php/index/management/settings/email"

        try:
            resp = self.session.get(template_url, timeout=self.REQUEST_TIMEOUT)
            if resp.status_code != 200:
                return findings
        except requests.RequestException:
            return findings

        csrf_token = self._extract_csrf(resp.text)

        for payload, expected in SSTI_PAYLOADS:
            try:
                post_data = {
                    "subject": f"Test Email {payload}",
                    "body": f"Email body with {payload} injection test",
                    "csrfToken": csrf_token or "",
                }

                # Coba submit dan ambil preview/response
                resp = self.session.post(
                    template_url,
                    data=post_data,
                    timeout=self.REQUEST_TIMEOUT,
                    allow_redirects=True,
                )

                if expected in resp.text:
                    findings.append(Finding(
                        title="Server-Side Template Injection (SSTI) di Email Template",
                        severity="critical",
                        description=(
                            f"Email template admin OJS rentan terhadap SSTI. "
                            f"Payload '{payload}' dievaluasi oleh template engine dan "
                            f"menghasilkan output '{expected}'. "
                            "SSTI dapat dieksploitasi untuk Remote Code Execution di server."
                        ),
                        evidence=f"Payload: {payload!r}, Output yang diharapkan '{expected}' ditemukan di response",
                        module=self.name,
                        remediation=(
                            "Jangan izinkan input user dievaluasi sebagai template code. "
                            "Sandbox template engine OJS. Update ke versi terbaru. "
                            "Validasi dan escape semua konten email template."
                        ),
                        url=template_url,
                        extra={"cwe_id": "CWE-94", "payload": payload},
                    ))
                    return findings  # Stop setelah temuan pertama

            except requests.RequestException:
                continue

        return findings

    def _check_crlf_injection(self) -> list[Finding]:
        """
        Test CRLF injection di field yang masuk ke email header.
        Targeted ke fitur bulk notification/email OJS.
        """
        findings = []
        notify_url = f"{self.target_url}/index.php/index/notification/sendNotification"

        crlf_payload = "OJS Security Test\r\nBcc: test@evil.example.com"

        try:
            resp = self.session.get(notify_url, timeout=self.REQUEST_TIMEOUT)
            if resp.status_code not in (200, 403):
                return findings
        except requests.RequestException:
            return findings

        csrf_token = self._extract_csrf(resp.text) if hasattr(resp, 'text') else None

        try:
            post_data = {
                "subject": crlf_payload,
                "message": "Test notification body",
                "csrfToken": csrf_token or "",
            }
            resp = self.session.post(
                notify_url,
                data=post_data,
                timeout=self.REQUEST_TIMEOUT,
            )

            # Cek apakah CRLF payload muncul di response tanpa encoding
            if "\r\n" in resp.text or "Bcc: test@evil.example.com" in resp.text:
                findings.append(Finding(
                    title="CRLF Injection di Email Header (Notification System)",
                    severity="medium",
                    description=(
                        "Field subject di sistem notifikasi email OJS tidak memfilter "
                        "karakter CRLF (\\r\\n). Ini memungkinkan attacker untuk "
                        "menginjeksi header email tambahan (seperti Bcc, Cc) dan "
                        "menggunakan server OJS sebagai relay spam."
                    ),
                    evidence=f"CRLF payload berhasil masuk ke response tanpa sanitasi",
                    module=self.name,
                    remediation=(
                        "Filter karakter \\r\\n dari semua field yang digunakan sebagai "
                        "email header. Gunakan library email yang aman dan validasi input."
                    ),
                    url=notify_url,
                    extra={"cwe_id": "CWE-93"},
                ))

        except requests.RequestException:
            pass

        return findings

    def _extract_csrf(self, html: str) -> str | None:
        """Ekstrak CSRF token dari HTML."""
        patterns = [
            r'<input[^>]+name=["\']csrfToken["\'][^>]+value=["\']([^"\']+)["\']',
            r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']csrfToken["\']',
            r'"csrfToken"\s*:\s*"([^"]+)"',
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
