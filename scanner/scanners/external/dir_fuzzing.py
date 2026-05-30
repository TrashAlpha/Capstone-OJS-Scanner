"""
scanners/external/dir_fuzzing.py
Fuzzing path dan direktori sensitif OJS (unauthenticated).

Menggunakan curated wordlist path OJS — bukan generic wordlist besar.
Deteksi file konfigurasi, direktori tersembunyi, dan endpoint berbahaya
yang seharusnya tidak dapat diakses publik.
"""

import requests
from scanners.base import ScannerModule, Finding


# Path sensitif yang spesifik untuk OJS
# Format: (path, label, severity, deskripsi)
OJS_SENSITIVE_PATHS = [
    # Config files — CRITICAL jika terekspos
    ("/config.inc.php",       "OJS Config File",        "critical",
     "File konfigurasi utama OJS berisi kredensial database, secret key, dan konfigurasi server."),
    ("/config.inc.php.bak",   "OJS Config Backup",      "critical",
     "File backup konfigurasi OJS berisi informasi sensitif yang sama dengan config.inc.php."),
    ("/config.inc.php~",      "OJS Config Temp File",   "critical",
     "File temporary editor teks berisi konten config.inc.php."),
    ("/config.inc.php.old",   "OJS Config Old Version", "high",
     "Versi lama config.inc.php yang mungkin masih berisi kredensial valid."),

    # Git repository
    ("/.git/config",          "Git Config Exposed",     "critical",
     "File .git/config terekspos — attacker bisa mengakses seluruh source code via git clone."),
    ("/.git/HEAD",            "Git HEAD Exposed",       "high",
     ".git/HEAD terekspos, mengkonfirmasi repositori git dapat diakses publik."),

    # Direktori file sensitif
    ("/files/",               "OJS Files Directory",    "high",
     "Direktori /files/ berisi submission dan file upload pengguna. Seharusnya tidak accessible publik."),
    ("/cache/",               "OJS Cache Directory",    "medium",
     "Direktori cache OJS dapat mengandung data sensitif yang di-cache."),
    ("/backup/",              "Backup Directory",       "high",
     "Direktori backup terdeteksi — mungkin berisi dump database atau file konfigurasi."),
    ("/logs/",                "Log Directory",          "medium",
     "Direktori log terekspos — berisi informasi aktivitas server dan error yang sensitif."),

    # Library dan tools
    ("/lib/pkp/",             "PKP Library Exposed",    "low",
     "Library PKP terekspos. Attacker dapat mempelajari versi library untuk mencari exploit."),
    ("/tools/",               "OJS Tools Directory",    "medium",
     "Direktori tools berisi script maintenance OJS yang seharusnya tidak publik."),

    # Upload dan public files
    ("/public/uploads/",      "Public Uploads",         "low",
     "Direktori public uploads — cek apakah berisi file berbahaya yang terupload."),
    ("/upload/",              "Upload Directory",        "medium",
     "Direktori upload terdeteksi di root — mungkin salah konfigurasi."),

    # Endpoint installer
    ("/index.php/index/install",         "OJS Installer Active",   "high",
     "Halaman installer OJS masih aktif. Dapat digunakan untuk re-install OJS."),
    ("/index.php/index/install/install", "OJS Installer Install",  "high",
     "Endpoint installer OJS aktif dan dapat diakses."),

    # phpinfo dan debugging
    ("/phpinfo.php",          "phpinfo() Exposed",      "high",
     "Halaman phpinfo() mengekspos konfigurasi PHP lengkap, termasuk path dan extension."),
    ("/info.php",             "PHP Info Page",          "high",
     "Halaman informasi PHP terekspos — informasi konfigurasi server terlihat publik."),
    ("/test.php",             "PHP Test Page",          "medium",
     "Halaman test PHP terekspos yang mungkin berisi informasi debug."),
]

# Keyword yang mengindikasikan konten sensitif di response body
SENSITIVE_INDICATORS = {
    "/config.inc.php":   ["database", "password", "driver", "ojs_default"],
    "/.git/config":      ["[core]", "[remote", "repositoryformat"],
    "/phpinfo.php":      ["PHP Version", "phpinfo()", "Server API"],
    "/info.php":         ["PHP Version", "phpinfo()", "Server API"],
    "/files/":           ["Index of", "Parent Directory"],
    "/backup/":          ["Index of", "Parent Directory", ".sql", ".tar"],
}


class DirFuzzingScanner(ScannerModule):
    name = "dir_fuzzing"

    REQUEST_TIMEOUT = 8

    def run(self, **kwargs) -> dict:
        findings = []

        for path, label, severity, description in OJS_SENSITIVE_PATHS:
            finding = self._probe_path(path, label, severity, description)
            if finding:
                findings.append(finding)

        return self.result(findings)

    def _probe_path(self, path: str, label: str, severity: str, description: str) -> Finding | None:
        """Probe satu path dengan HEAD request, fallback ke GET jika perlu verifikasi."""
        url = f"{self.target_url}{path}"

        try:
            # HEAD request dulu untuk efisiensi
            resp = requests.head(url, timeout=self.REQUEST_TIMEOUT, allow_redirects=True)

            if resp.status_code not in (200, 403):
                return None

            # Status 200 → mungkin ada konten, GET untuk verifikasi
            if resp.status_code == 200:
                get_resp = requests.get(url, timeout=self.REQUEST_TIMEOUT)
                body = get_resp.text

                # Verifikasi dengan keyword spesifik jika ada
                indicators = SENSITIVE_INDICATORS.get(path)
                if indicators:
                    if not any(ind.lower() in body.lower() for ind in indicators):
                        return None  # False positive — konten tidak sesuai

                evidence = f"GET {url} → HTTP 200"
                if indicators:
                    matched = [ind for ind in indicators if ind.lower() in body.lower()]
                    if matched:
                        evidence += f"\nKeyword sensitif ditemukan: {', '.join(matched[:3])}"

            elif resp.status_code == 403:
                # 403 = ada tapi terblokir — masih informatif tapi severity lebih rendah
                severity = "low" if severity in ("critical", "high") else "info"
                evidence = f"HEAD {url} → HTTP 403 (ada tapi akses diblokir)"
            else:
                return None

            remediation_map = {
                "critical": (
                    "Segera blokir akses ke path ini di konfigurasi web server (Nginx/Apache). "
                    "Pindahkan file sensitif ke luar document root web server."
                ),
                "high": (
                    "Tambahkan rule di .htaccess atau Nginx config untuk memblokir akses publik "
                    "ke direktori/file ini."
                ),
                "medium": (
                    "Periksa apakah direktori ini perlu dapat diakses publik. "
                    "Jika tidak, blokir dengan web server config."
                ),
                "low": (
                    "Pertimbangkan untuk menyembunyikan path ini dari publik."
                ),
            }

            return Finding(
                title=f"Path Sensitif Terekspos: {label}",
                severity=severity,
                description=description,
                evidence=evidence,
                module=self.name,
                remediation=remediation_map.get(severity, ""),
                url=url,
                extra={"cwe_id": "CWE-538" if "config" in path.lower() else "CWE-548"},
            )

        except requests.RequestException:
            return None
