"""
scanners/internal/idor.py
Deteksi Insecure Direct Object Reference (IDOR) di OJS.

Enumerate ID submissions/users dan test apakah user aktif bisa
mengakses resource milik user lain yang seharusnya privat.
"""

import json
import requests
from scanners.base import ScannerModule, Finding


class IDORScanner(ScannerModule):
    name = "idor_scanner"

    REQUEST_TIMEOUT = 10
    MAX_ID_PROBE = 20  # Probe ID 1 sampai N

    def run(self, **kwargs) -> dict:
        findings = []

        if not self.session:
            findings.append(Finding(
                title="Internal Scanner: Session Tidak Tersedia",
                severity="info",
                description="IDORScanner memerlukan sesi terotentikasi.",
                evidence="session=None",
                module=self.name,
            ))
            return self.result(findings)

        # Ambil identitas user aktif dulu
        current_user = self._get_current_user()

        findings.extend(self._check_submission_idor(current_user))
        findings.extend(self._check_user_data_idor(current_user))
        findings.extend(self._check_galley_idor())

        return self.result(findings, raw={"current_user": current_user})

    # ── Checks ─────────────────────────────────────────────────

    def _get_current_user(self) -> dict:
        """Ambil data user aktif dari REST API."""
        try:
            resp = self.session.get(
                f"{self.target_url}/api/v1/users/me",
                timeout=self.REQUEST_TIMEOUT,
            )
            if resp.status_code == 200:
                return resp.json()
        except (requests.RequestException, ValueError):
            pass
        return {}

    def _check_submission_idor(self, current_user: dict) -> list[Finding]:
        """
        Test apakah user bisa mengakses submissions milik user lain.
        Enumerate submission ID 1 sampai MAX_ID_PROBE.
        """
        findings = []
        current_user_id = current_user.get("id")
        idor_found = []

        for sub_id in range(1, self.MAX_ID_PROBE + 1):
            url = f"{self.target_url}/api/v1/submissions/{sub_id}"
            try:
                resp = self.session.get(url, timeout=self.REQUEST_TIMEOUT)

                if resp.status_code != 200:
                    continue

                data = resp.json()

                # Cek apakah submission ini milik user lain
                submitter_id = data.get("submitterId") or data.get("userId")
                if submitter_id and current_user_id and submitter_id != current_user_id:
                    idor_found.append({
                        "submission_id": sub_id,
                        "submitter_id": submitter_id,
                        "url": url,
                        "status": data.get("status"),
                    })

                if len(idor_found) >= 3:
                    break  # Cukup 3 bukti

            except (requests.RequestException, ValueError):
                continue

        if idor_found:
            evidence_lines = [
                f"  - Submission #{item['submission_id']} (pemilik: userId={item['submitter_id']}, status={item['status']})"
                for item in idor_found
            ]
            findings.append(Finding(
                title="IDOR: Akses ke Submission Milik User Lain",
                severity="high",
                description=(
                    "User dapat mengakses detail submission yang bukan miliknya melalui "
                    "REST API dengan hanya mengubah ID numerik. Ini dapat mengekspos "
                    "konten penelitian, data pribadi penulis, dan ulasan yang bersifat rahasia."
                ),
                evidence="Submission yang berhasil diakses:\n" + "\n".join(evidence_lines),
                module=self.name,
                remediation=(
                    "Tambahkan validasi kepemilikan di REST API /api/v1/submissions/{id}. "
                    "Pastikan hanya submitter, editor yang ditugaskan, dan admin yang "
                    "bisa mengakses detail submission tertentu."
                ),
                url=f"{self.target_url}/api/v1/submissions/",
                extra={"cwe_id": "CWE-639", "idor_samples": idor_found},
            ))

        return findings

    def _check_user_data_idor(self, current_user: dict) -> list[Finding]:
        """
        Test apakah user bisa mengakses profil/data user lain via REST API.
        """
        findings = []
        current_user_id = current_user.get("id")
        idor_found = []

        for user_id in range(1, min(self.MAX_ID_PROBE, 11)):
            if user_id == current_user_id:
                continue  # Skip data diri sendiri

            url = f"{self.target_url}/api/v1/users/{user_id}"
            try:
                resp = self.session.get(url, timeout=self.REQUEST_TIMEOUT)

                if resp.status_code != 200:
                    continue

                data = resp.json()
                # Cek apakah data berisi informasi sensitif
                sensitive_fields = [k for k in ("email", "phone", "country", "mailingAddress")
                                    if data.get(k)]
                if sensitive_fields:
                    idor_found.append({
                        "user_id": user_id,
                        "exposed_fields": sensitive_fields,
                        "username": data.get("userName", "unknown"),
                    })

                if len(idor_found) >= 3:
                    break

            except (requests.RequestException, ValueError):
                continue

        if idor_found:
            evidence_lines = [
                f"  - User #{item['user_id']} ({item['username']}): {', '.join(item['exposed_fields'])}"
                for item in idor_found
            ]
            findings.append(Finding(
                title="IDOR: Data Privat User Lain Dapat Diakses",
                severity="high",
                description=(
                    "REST API /api/v1/users/{id} mengekspos data privat pengguna lain "
                    "(email, telepon, alamat) hanya dengan mengubah ID di URL. "
                    "Ini melanggar privasi user dan dapat digunakan untuk phishing atau spam."
                ),
                evidence="Data user yang berhasil diakses:\n" + "\n".join(evidence_lines),
                module=self.name,
                remediation=(
                    "Batasi endpoint /api/v1/users/{id} agar hanya mengembalikan data publik "
                    "untuk user lain. Data sensitif hanya boleh diakses oleh user itu sendiri "
                    "atau admin."
                ),
                url=f"{self.target_url}/api/v1/users/",
                extra={"cwe_id": "CWE-639", "idor_samples": idor_found},
            ))

        return findings

    def _check_galley_idor(self) -> list[Finding]:
        """
        Test apakah file galley artikel yang belum dipublish bisa diakses.
        Artikel unpublished seharusnya tidak bisa didownload siapapun selain admin/editor.
        """
        findings = []
        accessible_unpublished = []

        for article_id in range(1, self.MAX_ID_PROBE + 1):
            # Cek status artikel via API dulu
            try:
                resp = self.session.get(
                    f"{self.target_url}/api/v1/submissions/{article_id}",
                    timeout=self.REQUEST_TIMEOUT,
                )
                if resp.status_code != 200:
                    continue

                data = resp.json()
                status = data.get("status")

                # Status 1 = unpublished/draft di OJS
                if status not in (1, "queued", "draft"):
                    continue

                # Coba akses galley article
                galley_url = f"{self.target_url}/index.php/index/article/view/{article_id}"
                galley_resp = self.session.get(galley_url, timeout=self.REQUEST_TIMEOUT, allow_redirects=True)

                if galley_resp.status_code == 200 and len(galley_resp.text) > 1000:
                    accessible_unpublished.append({
                        "article_id": article_id,
                        "status": status,
                        "url": galley_url,
                    })

                if len(accessible_unpublished) >= 2:
                    break

            except (requests.RequestException, ValueError):
                continue

        if accessible_unpublished:
            evidence_lines = [
                f"  - Artikel #{item['article_id']} (status: {item['status']}) → {item['url']}"
                for item in accessible_unpublished
            ]
            findings.append(Finding(
                title="IDOR: File Artikel Belum Dipublish Dapat Diakses",
                severity="medium",
                description=(
                    "Halaman artikel yang belum dipublish dapat diakses oleh user biasa. "
                    "Ini mengekspos konten penelitian sebelum review selesai dan "
                    "dapat melanggar hak cipta atau proses peer-review yang anonim."
                ),
                evidence="Artikel unpublished yang berhasil diakses:\n" + "\n".join(evidence_lines),
                module=self.name,
                remediation=(
                    "Pastikan OJS memvalidasi status publikasi sebelum menampilkan konten artikel. "
                    "Hanya admin, editor, dan penulis terkait yang boleh melihat draft artikel."
                ),
                url=f"{self.target_url}/index.php/index/article/",
                extra={"cwe_id": "CWE-639"},
            ))

        return findings
