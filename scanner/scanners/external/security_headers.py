"""
scanners/external/security_headers.py
Audit HTTP security headers pada target OJS.

Cek header yang WAJIB ada dan header yang SEBAIKNYA tidak ada
(karena mengekspos informasi server).
"""

import requests
from scanners.base import ScannerModule, Finding


# ── Header yang wajib ada ──────────────────────────────────────
REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "high",
        "description": (
            "CSP tidak dikonfigurasi. Tanpa header ini, browser tidak punya "
            "instruksi untuk memblokir script berbahaya — serangan XSS jadi "
            "jauh lebih mudah berhasil."
        ),
        "remediation": (
            "Tambahkan header Content-Security-Policy. "
            "Contoh minimal: Content-Security-Policy: default-src 'self'"
        ),
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": (
            "X-Frame-Options tidak ada. Halaman bisa di-embed di iframe "
            "oleh situs lain — membuka celah Clickjacking."
        ),
        "remediation": "Tambahkan: X-Frame-Options: DENY atau SAMEORIGIN",
    },
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": (
            "HSTS tidak dikonfigurasi. Koneksi HTTPS bisa di-downgrade "
            "ke HTTP oleh man-in-the-middle attack."
        ),
        "remediation": (
            "Tambahkan: Strict-Transport-Security: "
            "max-age=31536000; includeSubDomains"
        ),
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": (
            "Header ini tidak ada. Browser bisa menebak tipe konten "
            "(MIME sniffing) yang bisa dimanfaatkan untuk XSS."
        ),
        "remediation": "Tambahkan: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy tidak dikonfigurasi.",
        "remediation": (
            "Tambahkan: Referrer-Policy: strict-origin-when-cross-origin"
        ),
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": (
            "Permissions-Policy tidak ada. Fitur browser seperti kamera, "
            "mikrofon, dan geolokasi tidak dibatasi."
        ),
        "remediation": (
            "Tambahkan: Permissions-Policy: "
            "camera=(), microphone=(), geolocation=()"
        ),
    },
}

# ── Header yang TIDAK boleh ada (mengekspos info server) ───────
DANGEROUS_HEADERS = {
    "Server": {
        "severity": "low",
        "description": (
            "Header Server mengekspos informasi software webserver "
            "(misal: Apache/2.4.41). Informasi ini membantu attacker "
            "mencari exploit yang spesifik."
        ),
        "remediation": (
            "Sembunyikan versi di konfigurasi webserver. "
            "Nginx: server_tokens off; "
            "Apache: ServerTokens Prod"
        ),
    },
    "X-Powered-By": {
        "severity": "low",
        "description": (
            "Header X-Powered-By mengekspos teknologi backend "
            "(misal: PHP/8.1.0). Memudahkan attacker fingerprinting."
        ),
        "remediation": (
            "PHP: expose_php = Off di php.ini. "
            "Laravel: sudah otomatis hapus header ini jika pakai Nginx."
        ),
    },
    "X-AspNet-Version": {
        "severity": "low",
        "description": "Mengekspos versi ASP.NET yang digunakan.",
        "remediation": "Nonaktifkan di web.config: <httpRuntime enableVersionHeader='false'/>",
    },
}


class SecurityHeadersScanner(ScannerModule):
    name = "security_headers"

    def run(self, **kwargs) -> dict:
        findings = []
        headers_found = {}

        try:
            resp = requests.get(
                self.target_url,
                timeout=10,
                # Ikuti redirect — cek header di halaman akhir
                allow_redirects=True,
            )
            # Normalisasi key jadi lowercase untuk perbandingan
            headers_found = {k.lower(): v for k, v in resp.headers.items()}

        except requests.RequestException as e:
            findings.append(Finding(
                title="Gagal Mengambil Response Header",
                severity="info",
                description=f"Scanner tidak bisa terhubung ke target: {e}",
                evidence=str(e),
                module=self.name,
                url=self.target_url,
            ))
            return self.result(findings)

        # ── Cek header yang wajib ada ──────────────────────────
        for header_name, info in REQUIRED_HEADERS.items():
            if header_name.lower() not in headers_found:
                findings.append(Finding(
                    title=f"Header Keamanan Hilang: {header_name}",
                    severity=info["severity"],
                    description=info["description"],
                    evidence=(
                        f"Header '{header_name}' tidak ditemukan "
                        f"di response {self.target_url}"
                    ),
                    module=self.name,
                    remediation=info["remediation"],
                    url=self.target_url,
                ))

        # ── Cek header yang tidak boleh ada ────────────────────
        for header_name, info in DANGEROUS_HEADERS.items():
            if header_name.lower() in headers_found:
                header_value = headers_found[header_name.lower()]
                findings.append(Finding(
                    title=f"Header Mengekspos Info Server: {header_name}",
                    severity=info["severity"],
                    description=info["description"],
                    evidence=f"{header_name}: {header_value}",
                    module=self.name,
                    remediation=info["remediation"],
                    url=self.target_url,
                ))

        # ── Cek khusus: CSP ada tapi terlalu lemah ─────────────
        csp_value = headers_found.get("content-security-policy", "")
        if csp_value and "unsafe-inline" in csp_value:
            findings.append(Finding(
                title="CSP Lemah: Mengizinkan 'unsafe-inline'",
                severity="medium",
                description=(
                    "Content-Security-Policy ada tapi mengandung 'unsafe-inline' "
                    "yang membatalkan perlindungan XSS dari CSP."
                ),
                evidence=f"Content-Security-Policy: {csp_value}",
                module=self.name,
                remediation=(
                    "Hapus 'unsafe-inline' dari CSP. "
                    "Gunakan nonce atau hash untuk inline script yang dibutuhkan."
                ),
                url=self.target_url,
            ))

        # ── Cek HSTS ada tapi max-age terlalu pendek ───────────
        hsts_value = headers_found.get("strict-transport-security", "")
        if hsts_value:
            match = __import__("re").search(r"max-age=(\d+)", hsts_value)
            if match and int(match.group(1)) < 31536000:
                findings.append(Finding(
                    title="HSTS max-age Terlalu Pendek",
                    severity="low",
                    description=(
                        f"HSTS max-age={match.group(1)} detik (kurang dari 1 tahun). "
                        "Rekomendasi minimum adalah 31536000 (1 tahun)."
                    ),
                    evidence=f"Strict-Transport-Security: {hsts_value}",
                    module=self.name,
                    remediation=(
                        "Set max-age minimal 31536000. "
                        "Tambahkan includeSubDomains jika memungkinkan."
                    ),
                    url=self.target_url,
                ))

        return self.result(
            findings,
            raw={"headers_received": dict(resp.headers)},
        )