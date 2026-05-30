"""
scanners/internal/broken_access.py
Deteksi Broken Access Control dan Privilege Escalation di OJS.

Test apakah user dengan role tertentu bisa mengakses endpoint
yang seharusnya dibatasi untuk role yang lebih tinggi.
"""

import requests
from scanners.base import ScannerModule, Finding


# Endpoint admin yang hanya boleh diakses oleh admin site
ADMIN_ONLY_ENDPOINTS = [
    ("/index.php/index/admin", "Admin Dashboard"),
    ("/index.php/index/admin/users", "User Management"),
    ("/index.php/index/admin/plugins", "Plugin Management"),
    ("/index.php/index/admin/settings", "System Settings"),
    ("/index.php/index/admin/contexts", "Journal Manager"),
    ("/index.php/index/admin/jobs", "Scheduled Jobs"),
]

# Endpoint manajemen journal (butuh setidaknya editor/manager)
JOURNAL_MANAGER_ENDPOINTS = [
    ("/index.php/index/management/settings/context", "Journal Settings"),
    ("/index.php/index/management/settings/website", "Website Settings"),
    ("/index.php/index/management/settings/workflow", "Workflow Settings"),
    ("/index.php/index/management/users", "Journal Users"),
]


class BrokenAccessScanner(ScannerModule):
    name = "broken_access"

    REQUEST_TIMEOUT = 10

    def run(self, **kwargs) -> dict:
        findings = []

        if not self.session:
            findings.append(Finding(
                title="Internal Scanner: Session Tidak Tersedia",
                severity="info",
                description="BrokenAccessScanner memerlukan sesi terotentikasi.",
                evidence="session=None",
                module=self.name,
            ))
            return self.result(findings)

        # Deteksi role user dari session aktif
        role = self._detect_current_role()

        findings.extend(self._check_admin_panel_access(role))
        findings.extend(self._check_horizontal_privilege_escalation(role))
        findings.extend(self._check_api_access_control())

        return self.result(findings, raw={"detected_role": role})

    # ── Checks ─────────────────────────────────────────────────

    def _detect_current_role(self) -> str:
        """Coba deteksi role user aktif dari session."""
        # Cek apakah bisa akses admin panel
        try:
            resp = self.session.get(
                f"{self.target_url}/index.php/index/admin",
                timeout=self.REQUEST_TIMEOUT,
                allow_redirects=False,
            )
            if resp.status_code == 200:
                return "admin"
        except requests.RequestException:
            pass

        # Cek editor/manager
        try:
            resp = self.session.get(
                f"{self.target_url}/index.php/index/management/settings/context",
                timeout=self.REQUEST_TIMEOUT,
                allow_redirects=False,
            )
            if resp.status_code == 200:
                return "editor"
        except requests.RequestException:
            pass

        return "author_or_reader"

    def _check_admin_panel_access(self, current_role: str) -> list[Finding]:
        """
        Test akses ke endpoint admin.
        Jika user bukan admin tapi bisa akses endpoint admin → Broken Access Control.
        """
        findings = []

        # Jika user sudah admin, test akses horizontal antar journal saja
        if current_role == "admin":
            return findings

        accessible = []
        for path, label in ADMIN_ONLY_ENDPOINTS:
            url = f"{self.target_url}{path}"
            try:
                resp = self.session.get(
                    url,
                    timeout=self.REQUEST_TIMEOUT,
                    allow_redirects=False,
                )
                # 200 = langsung dapat konten (bypass!), bukan 302 redirect
                if resp.status_code == 200:
                    # Verifikasi ini bukan halaman error atau redirect halus
                    if len(resp.text) > 500 and "login" not in resp.url.lower():
                        accessible.append(f"{label} ({path})")
            except requests.RequestException:
                continue

        if accessible:
            findings.append(Finding(
                title="Broken Access Control: Endpoint Admin Dapat Diakses",
                severity="critical",
                description=(
                    f"User dengan role '{current_role}' dapat mengakses endpoint admin "
                    f"yang seharusnya memerlukan role Admin. Ini adalah Broken Access Control "
                    f"yang memungkinkan privilege escalation penuh."
                ),
                evidence=f"Endpoint admin yang berhasil diakses:\n" + "\n".join(f"  - {e}" for e in accessible),
                module=self.name,
                cve="CWE-285",
                remediation=(
                    "Periksa konfigurasi role dan permission di OJS. Pastikan middleware "
                    "autentikasi admin berjalan di semua route /admin/. "
                    "Update OJS ke versi terbaru yang memiliki perbaikan akses kontrol."
                ),
                url=f"{self.target_url}/index.php/index/admin",
                extra={"cwe_id": "CWE-285", "accessible_endpoints": accessible},
            ))

        return findings

    def _check_horizontal_privilege_escalation(self, current_role: str) -> list[Finding]:
        """
        Test akses ke resource journal lain (horizontal privilege escalation).
        Relevan jika user adalah editor/manager di satu journal.
        """
        findings = []

        if current_role not in ("editor", "author_or_reader"):
            return findings

        # Coba akses journal settings dengan index journal yang berbeda (1, 2, 3)
        accessible_journals = []
        for journal_idx in range(1, 4):
            url = f"{self.target_url}/index.php/journal{journal_idx}/management/settings/context"
            try:
                resp = self.session.get(
                    url,
                    timeout=self.REQUEST_TIMEOUT,
                    allow_redirects=False,
                )
                if resp.status_code == 200 and len(resp.text) > 500:
                    accessible_journals.append(url)
            except requests.RequestException:
                continue

        if len(accessible_journals) > 1:
            findings.append(Finding(
                title="Horizontal Privilege Escalation: Akses ke Journal Lain",
                severity="high",
                description=(
                    "User dapat mengakses settings journal lain yang bukan miliknya. "
                    "Ini adalah Horizontal Privilege Escalation — user bisa memodifikasi "
                    "konfigurasi journal yang tidak berada di bawah role-nya."
                ),
                evidence=f"Journal yang dapat diakses:\n" + "\n".join(f"  - {j}" for j in accessible_journals),
                module=self.name,
                remediation=(
                    "Pastikan OJS memvalidasi kepemilikan journal sebelum mengizinkan "
                    "akses ke settings. Periksa konfigurasi multi-journal."
                ),
                url=accessible_journals[0],
                extra={"cwe_id": "CWE-639"},
            ))

        return findings

    def _check_api_access_control(self) -> list[Finding]:
        """Test akses kontrol di REST API OJS v1."""
        findings = []

        # Test akses ke user list via REST API (seharusnya butuh admin)
        api_endpoints = [
            ("/api/v1/users", "User List API"),
            ("/api/v1/contexts", "Journal Contexts API"),
        ]

        for path, label in api_endpoints:
            url = f"{self.target_url}{path}"
            try:
                resp = self.session.get(url, timeout=self.REQUEST_TIMEOUT)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        # Cek apakah response berisi data user (bukan error)
                        if isinstance(data, (list, dict)) and len(str(data)) > 100:
                            findings.append(Finding(
                                title=f"API Access Control Lemah: {label} Dapat Diakses",
                                severity="medium",
                                description=(
                                    f"Endpoint REST API '{path}' dapat diakses dan mengembalikan "
                                    f"data yang seharusnya dibatasi. Ini bisa mengekspos "
                                    f"informasi user atau konfigurasi sistem ke role yang tidak berhak."
                                ),
                                evidence=f"GET {url} → HTTP 200, data length: {len(str(data))} chars",
                                module=self.name,
                                remediation=(
                                    "Periksa permission policy di OJS REST API. "
                                    "Tambahkan middleware autentikasi role yang tepat di setiap endpoint."
                                ),
                                url=url,
                                extra={"cwe_id": "CWE-285"},
                            ))
                    except (ValueError, KeyError):
                        pass
            except requests.RequestException:
                continue

        return findings
