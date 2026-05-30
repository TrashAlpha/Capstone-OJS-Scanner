"""
scanners/internal/security_audit.py
Audit konfigurasi keamanan OJS dari perspektif admin.

Tidak mengirim payload berbahaya — hanya membaca dan menganalisis
konfigurasi yang terlihat di panel admin. Butuh sesi terotentikasi.
"""

import re
import requests
from scanners.base import ScannerModule, Finding


# File extension yang berbahaya jika diizinkan untuk diupload
DANGEROUS_EXTENSIONS = {"php", "php3", "php4", "php5", "phtml", "sh", "bash",
                        "exe", "bat", "cmd", "ps1", "py", "rb", "pl", "asp", "aspx"}

# Kredensial default OJS yang umum digunakan
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "ojs"),
    ("admin", "admin123"),
]


class SecurityAuditScanner(ScannerModule):
    name = "security_audit"

    REQUEST_TIMEOUT = 10

    def run(self, **kwargs) -> dict:
        findings = []

        findings.extend(self._check_default_credentials())
        findings.extend(self._check_installer_active())
        findings.extend(self._check_upload_file_types())
        findings.extend(self._check_password_policy())
        findings.extend(self._check_captcha_enabled())
        findings.extend(self._check_debug_info_exposure())

        return self.result(findings)

    # ── Checks ─────────────────────────────────────────────────

    def _check_default_credentials(self) -> list[Finding]:
        """Test apakah OJS menggunakan kredensial default yang lemah."""
        findings = []
        login_url = f"{self.target_url}/index.php/index/login/signIn"

        # Ambil CSRF token terlebih dahulu
        csrf_token = None
        try:
            resp = requests.get(
                f"{self.target_url}/index.php/index/login",
                timeout=self.REQUEST_TIMEOUT,
            )
            match = re.search(
                r'<input[^>]+name=["\']csrfToken["\'][^>]+value=["\']([^"\']+)["\']',
                resp.text,
                re.IGNORECASE,
            )
            if match:
                csrf_token = match.group(1)
        except requests.RequestException:
            return findings

        for username, password in DEFAULT_CREDENTIALS:
            try:
                form_data = {"username": username, "password": password}
                if csrf_token:
                    form_data["csrfToken"] = csrf_token

                session = requests.Session()
                resp = session.post(
                    login_url,
                    data=form_data,
                    timeout=self.REQUEST_TIMEOUT,
                    allow_redirects=True,
                )

                # Login berhasil jika tidak redirect kembali ke /login
                if "login" not in resp.url.lower() or "signout" in resp.text.lower():
                    findings.append(Finding(
                        title="Kredensial Default OJS Ditemukan",
                        severity="critical",
                        description=(
                            f"OJS menggunakan kombinasi username/password default "
                            f"'{username}/{password}'. Attacker dapat langsung login "
                            f"sebagai admin dan mengambil alih sistem."
                        ),
                        evidence=f"Login berhasil dengan username='{username}', password='{password}'",
                        module=self.name,
                        cve="CWE-521",
                        remediation=(
                            "Segera ganti password admin ke password yang kuat dan unik. "
                            "Gunakan minimal 12 karakter dengan kombinasi huruf, angka, dan simbol."
                        ),
                        url=login_url,
                        extra={"cwe_id": "CWE-521"},
                    ))
                    break  # Cukup satu temuan, tidak perlu test semua kombinasi

            except requests.RequestException:
                continue

        return findings

    def _check_installer_active(self) -> list[Finding]:
        """Cek apakah halaman installer masih aktif setelah instalasi."""
        findings = []
        install_urls = [
            f"{self.target_url}/index.php/index/install",
            f"{self.target_url}/index.php/index/install/install",
        ]

        for url in install_urls:
            try:
                resp = requests.get(url, timeout=self.REQUEST_TIMEOUT, allow_redirects=True)
                if resp.status_code == 200 and (
                    "install" in resp.text.lower() or
                    "database" in resp.text.lower() or
                    "setup" in resp.text.lower()
                ):
                    findings.append(Finding(
                        title="Halaman Installer OJS Masih Aktif",
                        severity="high",
                        description=(
                            "Endpoint installer OJS masih dapat diakses setelah instalasi selesai. "
                            "Attacker dapat menggunakan ini untuk re-instalasi OJS dengan "
                            "database baru, menghapus semua data, atau mengeksploitasi "
                            "kerentanan dalam proses instalasi."
                        ),
                        evidence=f"GET {url} → HTTP 200 dengan konten installer",
                        module=self.name,
                        remediation=(
                            "Hapus atau nonaktifkan direktori install/ setelah instalasi selesai. "
                            "Tambahkan konfigurasi web server untuk memblokir akses ke path ini."
                        ),
                        url=url,
                        extra={"cwe_id": "CWE-16"},
                    ))
                    break
            except requests.RequestException:
                continue

        return findings

    def _check_upload_file_types(self) -> list[Finding]:
        """Cek allowed file types di admin settings via session terotentikasi."""
        findings = []
        if not self.session:
            return findings

        settings_urls = [
            f"{self.target_url}/index.php/index/admin/settings",
            f"{self.target_url}/index.php/index/management/settings/website",
        ]

        for url in settings_urls:
            try:
                resp = self.session.get(url, timeout=self.REQUEST_TIMEOUT)
                if resp.status_code != 200:
                    continue

                # Cari setting allowed file types di HTML response
                # OJS biasanya ada field "uploadedFiles" atau "allowedFileTypes"
                dangerous_found = []
                for ext in DANGEROUS_EXTENSIONS:
                    patterns = [
                        rf'\b{re.escape(ext)}\b',
                        rf'\.{re.escape(ext)}\b',
                    ]
                    for pattern in patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            dangerous_found.append(ext)
                            break

                if dangerous_found:
                    findings.append(Finding(
                        title="Ekstensi File Berbahaya Diizinkan untuk Upload",
                        severity="high",
                        description=(
                            f"Konfigurasi OJS mengizinkan upload file dengan ekstensi berbahaya: "
                            f"{', '.join(sorted(set(dangerous_found)))}. "
                            "Jika file ini berhasil diupload dan diakses, dapat menyebabkan "
                            "Remote Code Execution di server."
                        ),
                        evidence=f"Ditemukan ekstensi berbahaya di settings: {', '.join(sorted(set(dangerous_found)))}",
                        module=self.name,
                        remediation=(
                            "Di Admin > Pengaturan > Website, batasi ekstensi yang diizinkan "
                            "hanya ke format dokumen aman: pdf, doc, docx, odt, txt, jpg, png."
                        ),
                        url=url,
                        extra={"cwe_id": "CWE-434", "dangerous_extensions": list(set(dangerous_found))},
                    ))
                    break

            except requests.RequestException:
                continue

        return findings

    def _check_password_policy(self) -> list[Finding]:
        """Cek kebijakan password di admin settings."""
        findings = []
        if not self.session:
            return findings

        settings_url = f"{self.target_url}/index.php/index/admin/settings"
        try:
            resp = self.session.get(settings_url, timeout=self.REQUEST_TIMEOUT)
            if resp.status_code != 200:
                return findings

            # Cari konfigurasi minimum password length
            # OJS: field "minPasswordLength" atau value di input
            match = re.search(
                r'minPasswordLength["\s:=]+(\d+)',
                resp.text,
                re.IGNORECASE,
            )
            if match:
                min_length = int(match.group(1))
                if min_length < 8:
                    findings.append(Finding(
                        title=f"Kebijakan Password Terlalu Lemah (min: {min_length} karakter)",
                        severity="medium",
                        description=(
                            f"Panjang minimum password dikonfigurasi hanya {min_length} karakter. "
                            "Password pendek mudah di-bruteforce. NIST merekomendasikan minimal 8 karakter, "
                            "idealnya 12+ karakter."
                        ),
                        evidence=f"minPasswordLength = {min_length} ditemukan di {settings_url}",
                        module=self.name,
                        remediation=(
                            "Naikkan minimum panjang password ke minimal 8 karakter di "
                            "Admin > Pengaturan > Keamanan."
                        ),
                        url=settings_url,
                        extra={"cwe_id": "CWE-521", "min_length": min_length},
                    ))

        except requests.RequestException:
            pass

        return findings

    def _check_captcha_enabled(self) -> list[Finding]:
        """Cek apakah captcha/spam protection aktif."""
        findings = []
        if not self.session:
            return findings

        settings_url = f"{self.target_url}/index.php/index/management/settings/website"
        try:
            resp = self.session.get(settings_url, timeout=self.REQUEST_TIMEOUT)
            if resp.status_code != 200:
                return findings

            # Cek indikasi captcha disabled
            if re.search(r'captcha.*?disabled|recaptcha.*?off|spam.*?protection.*?disabled',
                         resp.text, re.IGNORECASE):
                findings.append(Finding(
                    title="Proteksi Captcha/Spam Dinonaktifkan",
                    severity="low",
                    description=(
                        "Captcha atau proteksi spam tidak aktif. Tanpa captcha, "
                        "form registrasi dan komentar rentan terhadap spam dan "
                        "bot yang bisa membuat akun massal."
                    ),
                    evidence=f"Indikasi captcha disabled ditemukan di {settings_url}",
                    module=self.name,
                    remediation=(
                        "Aktifkan reCAPTCHA di Admin > Pengaturan > Website > Spam Protection."
                    ),
                    url=settings_url,
                    extra={"cwe_id": "CWE-693"},
                ))

        except requests.RequestException:
            pass

        return findings

    def _check_debug_info_exposure(self) -> list[Finding]:
        """Cek apakah debug mode aktif (error details terekspos ke user)."""
        findings = []
        test_urls = [
            f"{self.target_url}/index.php/index/nonexistent_page_xyz",
            f"{self.target_url}/index.php/index/admin/broken_endpoint_xyz",
        ]

        debug_patterns = [
            r"Stack trace:",
            r"on line \d+",
            r"Call Stack",
            r"Smarty Error",
            r"PHP Fatal error",
            r"APP_KEY",
            r"database.*password",
        ]

        for url in test_urls:
            try:
                session = self.session or requests.Session()
                resp = session.get(url, timeout=self.REQUEST_TIMEOUT)

                for pattern in debug_patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        findings.append(Finding(
                            title="Informasi Debug Terekspos ke Publik",
                            severity="medium",
                            description=(
                                "Halaman error OJS menampilkan informasi debug yang sensitif seperti "
                                "stack trace, path file server, atau konfigurasi internal. "
                                "Informasi ini membantu attacker memahami arsitektur sistem."
                            ),
                            evidence=f"Debug info ditemukan di error page: {url}",
                            module=self.name,
                            remediation=(
                                "Set 'show_stacktrace = Off' di config.inc.php. "
                                "Pastikan mode produksi diaktifkan bukan development mode."
                            ),
                            url=url,
                            extra={"cwe_id": "CWE-209"},
                        ))
                        return findings  # Cukup satu temuan

            except requests.RequestException:
                continue

        return findings
