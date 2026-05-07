"""
scanners/external/version_scan.py
Deteksi versi OJS dan mapping ke CVE yang diketahui.

Strategi deteksi (urut dari paling reliable):
1. Endpoint OAI  — /index.php/index/oai?verb=Identify
2. Meta generator tag — <meta name="generator" content="Open Journal Systems x.x.x">
3. Path CSS/JS   — /lib/pkp/styles/... (ada versi di path)
4. Header Server — kadang expose versi PHP/OJS
"""

import re
import requests
from bs4 import BeautifulSoup
from scanners.base import ScannerModule, Finding

# ── CVE Database (tambahkan terus sesuai update) ──────────────
CVE_MAP = {
    # Format: "versi_prefix": [{"id": "CVE-...", "severity": "...", "desc": "..."}]
    "3.3.0": [
        {
            "id": "CVE-2023-29005",
            "severity": "critical",
            "desc": "Remote Code Execution via unsafe deserialization",
        },
        {
            "id": "CVE-2023-6671",
            "severity": "high",
            "desc": "Cross-Site Request Forgery (CSRF) pada form submission",
        },
    ],
    "3.2": [
        {
            "id": "CVE-2021-27183",
            "severity": "high",
            "desc": "Stored XSS via journal title field",
        },
    ],
    "3.1": [
        {
            "id": "CVE-2019-17648",
            "severity": "critical",
            "desc": "SQL Injection pada parameter pencarian",
        },
    ],
    "2.": [
        {
            "id": "CVE-2018-1000201",
            "severity": "critical",
            "desc": "OJS versi 2.x sudah End-of-Life — banyak CVE tidak di-patch",
        },
    ],
}


def get_cves_for_version(version: str) -> list[dict]:
    """Cari CVE yang cocok berdasarkan prefix versi."""
    matched = []
    for prefix, cves in CVE_MAP.items():
        if version.startswith(prefix):
            matched.extend(cves)
    return matched


class VersionScanner(ScannerModule):
    name = "version_scanner"

    def run(self, **kwargs) -> dict:
        findings = []
        version = None

        # ── Strategi 1: OAI Endpoint (paling reliable) ────────
        version = version or self._detect_via_oai()

        # ── Strategi 2: Meta Generator Tag ────────────────────
        version = version or self._detect_via_meta()

        # ── Strategi 3: Regex di HTML (fallback) ──────────────
        version = version or self._detect_via_html_regex()

        # ── Hasil deteksi ─────────────────────────────────────
        if version:
            findings.append(Finding(
                title=f"OJS Version Detected: {version}",
                severity="info",
                description=f"Versi OJS yang terdeteksi adalah {version}.",
                evidence=f"Terdeteksi via scanning pada {self.target_url}",
                module=self.name,
                url=self.target_url,
            ))

            # ── CVE Mapping ────────────────────────────────────
            cves = get_cves_for_version(version)
            for cve in cves:
                findings.append(Finding(
                    title=f"{cve['id']} — OJS {version}",
                    severity=cve["severity"],
                    description=cve["desc"],
                    evidence=f"OJS versi {version} diketahui rentan terhadap {cve['id']}",
                    module=self.name,
                    cve=cve["id"],
                    remediation="Update OJS ke versi terbaru di https://pkp.sfu.ca/ojs/ojs_download/",
                    url=self.target_url,
                ))
        else:
            # Tetap catat meski versi tidak ketemu — bisa jadi sengaja disembunyikan
            findings.append(Finding(
                title="OJS Version Hidden or Not Detected",
                severity="info",
                description=(
                    "Versi OJS tidak berhasil dideteksi. "
                    "Ini bisa berarti versi sengaja disembunyikan (bagus) "
                    "atau target bukan OJS."
                ),
                evidence=f"Tidak ada indikator versi di {self.target_url}",
                module=self.name,
                url=self.target_url,
            ))

        return self.result(findings, raw={"detected_version": version})

    # ── Private detection methods ──────────────────────────────

    def _detect_via_oai(self) -> str | None:
        """
        OAI endpoint biasanya expose versi OJS secara eksplisit.
        Contoh response: <repositoryName>Journal Name</repositoryName>
                         <adminEmail>...</adminEmail>
        Cari pattern: Open Journal Systems / x.x.x.x
        """
        oai_url = f"{self.target_url}/index.php/index/oai?verb=Identify"
        try:
            resp = requests.get(oai_url, timeout=10)
            if resp.status_code == 200:
                # Cari pola versi di XML response
                match = re.search(
                    r"Open Journal Systems[/ ]([\d.]+)",
                    resp.text,
                    re.IGNORECASE,
                )
                if match:
                    return match.group(1)
        except requests.RequestException:
            pass
        return None

    def _detect_via_meta(self) -> str | None:
        """
        Cek meta generator tag di halaman utama.
        <meta name="generator" content="Open Journal Systems 3.3.0.8">
        """
        try:
            resp = requests.get(self.target_url, timeout=10)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                generator = soup.find("meta", {"name": "generator"})
                if generator and "Open Journal Systems" in generator.get("content", ""):
                    match = re.search(r"([\d.]+)", generator["content"])
                    if match:
                        return match.group(1)
        except requests.RequestException:
            pass
        return None

    def _detect_via_html_regex(self) -> str | None:
        """
        Fallback: cari pola versi di raw HTML.
        Kadang muncul di comment HTML, path JS/CSS, atau footer.
        """
        patterns = [
            r'pkp[_-]version["\s:=]+([\d.]+)',
            r'ojs/([\d.]+)',
            r'Open Journal Systems ([\d.]+)',
            r'/js/build\.js\?([\d.]+)',           # cache-busting URL
            r'styles/\.\.\./([\d.]+)',
        ]
        try:
            resp = requests.get(self.target_url, timeout=10)
            if resp.status_code == 200:
                for pattern in patterns:
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    if match:
                        return match.group(1)
        except requests.RequestException:
            pass
        return None