"""
scanners/internal/file_upload.py
Deteksi kelemahan validasi file upload di OJS.

Uji berbagai teknik bypass validasi file upload melalui
sistem submission OJS yang memerlukan autentikasi author/editor.
"""

import io
import re
import requests
from scanners.base import ScannerModule, Finding


# Content minimal PHP webshell untuk test (tidak aktif, hanya untuk cek validasi)
PHP_CONTENT = b"<?php echo 'OJS-UPLOAD-TEST'; ?>"
SVG_XSS_CONTENT = b'<svg xmlns="http://www.w3.org/2000/svg" onload="window.__svg_xss=1"><rect/></svg>'
HARMLESS_PDF_HEADER = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"


class FileUploadScanner(ScannerModule):
    name = "file_upload"

    REQUEST_TIMEOUT = 15

    def run(self, **kwargs) -> dict:
        findings = []

        if not self.session:
            findings.append(Finding(
                title="Internal Scanner: Session Tidak Tersedia",
                severity="info",
                description="FileUploadScanner memerlukan sesi terotentikasi.",
                evidence="session=None",
                module=self.name,
            ))
            return self.result(findings)

        # Temukan submission ID yang bisa digunakan untuk upload test
        submission_id = self._find_test_submission()

        if not submission_id:
            # Tidak ada submission — coba upload langsung ke endpoint generik
            findings.extend(self._check_direct_upload_endpoints())
        else:
            findings.extend(self._check_php_extension_bypass(submission_id))
            findings.extend(self._check_double_extension(submission_id))
            findings.extend(self._check_svg_xss_upload(submission_id))

        return self.result(findings, raw={"test_submission_id": submission_id})

    # ── Helpers ────────────────────────────────────────────────

    def _find_test_submission(self) -> int | None:
        """Cari submission aktif milik user sendiri untuk dijadikan target upload test."""
        try:
            resp = self.session.get(
                f"{self.target_url}/api/v1/submissions?status=1",
                timeout=self.REQUEST_TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", data) if isinstance(data, dict) else data
                if isinstance(items, list) and items:
                    return items[0].get("id")
        except (requests.RequestException, ValueError, KeyError):
            pass
        return None

    def _upload_file(self, submission_id: int, filename: str,
                     content: bytes, mime_type: str) -> requests.Response | None:
        """Helper: upload file ke submission via OJS REST API v1."""
        upload_url = f"{self.target_url}/api/v1/submissions/{submission_id}/files"
        try:
            files = {
                "file": (filename, io.BytesIO(content), mime_type),
            }
            data = {
                "fileStage": "2",  # 2 = submission files
                "name": filename,
            }
            resp = self.session.post(
                upload_url,
                files=files,
                data=data,
                timeout=self.REQUEST_TIMEOUT,
            )
            return resp
        except requests.RequestException:
            return None

    # ── Checks ─────────────────────────────────────────────────

    def _check_php_extension_bypass(self, submission_id: int) -> list[Finding]:
        """
        Test upload file .php dengan MIME type yang dimanipulasi menjadi application/pdf.
        Bypass: server percaya MIME type header, bukan ekstensi file.
        """
        findings = []
        resp = self._upload_file(
            submission_id,
            filename="research-paper.php",
            content=HARMLESS_PDF_HEADER + PHP_CONTENT,
            mime_type="application/pdf",  # Fake MIME
        )

        if resp and resp.status_code in (200, 201):
            try:
                data = resp.json()
                file_path = data.get("path") or data.get("url") or data.get("id")
                if file_path or data.get("fileStage"):
                    findings.append(Finding(
                        title="File Upload Bypass: PHP File Diterima dengan MIME application/pdf",
                        severity="critical",
                        description=(
                            "Server OJS menerima upload file .php dengan MIME type palsu 'application/pdf'. "
                            "Jika file ini dapat dieksekusi di server (misal: /files/ dapat diakses via HTTP), "
                            "attacker bisa menjalankan kode PHP arbitrary — Remote Code Execution penuh."
                        ),
                        evidence=(
                            f"Upload 'research-paper.php' berhasil (HTTP {resp.status_code}). "
                            f"File path/ID: {file_path}"
                        ),
                        module=self.name,
                        remediation=(
                            "Validasi ekstensi file di sisi server, bukan hanya MIME type. "
                            "Simpan file upload di direktori yang tidak dapat diakses via HTTP. "
                            "Rename semua file upload ke nama random tanpa ekstensi berbahaya. "
                            "Gunakan whitelist ekstensi yang diizinkan: pdf, doc, docx, odt, txt."
                        ),
                        url=f"{self.target_url}/api/v1/submissions/{submission_id}/files",
                        extra={"cwe_id": "CWE-434", "submission_id": submission_id},
                    ))
            except (ValueError, KeyError):
                pass

        return findings

    def _check_double_extension(self, submission_id: int) -> list[Finding]:
        """
        Test double extension bypass: shell.php.pdf
        Beberapa server hanya cek ekstensi terakhir (.pdf), tapi eksekusi berdasarkan yang pertama (.php).
        """
        findings = []
        resp = self._upload_file(
            submission_id,
            filename="shell.php.pdf",
            content=HARMLESS_PDF_HEADER + PHP_CONTENT,
            mime_type="application/pdf",
        )

        if resp and resp.status_code in (200, 201):
            try:
                data = resp.json()
                if data.get("fileStage") or data.get("id"):
                    findings.append(Finding(
                        title="File Upload Bypass: Double Extension (.php.pdf) Diterima",
                        severity="high",
                        description=(
                            "Server OJS menerima file dengan double extension 'shell.php.pdf'. "
                            "Tergantung konfigurasi web server, file ini mungkin dieksekusi "
                            "sebagai PHP script jika PHP handler dikonfigurasi untuk memproses "
                            "file yang mengandung '.php' di nama file."
                        ),
                        evidence=f"Upload 'shell.php.pdf' berhasil (HTTP {resp.status_code})",
                        module=self.name,
                        remediation=(
                            "Validasi ekstensi file dengan benar — gunakan ekstensi PALING AKHIR "
                            "dan pastikan tidak ada ekstensi PHP di bagian manapun dari nama file. "
                            "Gunakan fungsi pathinfo() yang aman untuk ekstrak ekstensi."
                        ),
                        url=f"{self.target_url}/api/v1/submissions/{submission_id}/files",
                        extra={"cwe_id": "CWE-434", "submission_id": submission_id},
                    ))
            except (ValueError, KeyError):
                pass

        return findings

    def _check_svg_xss_upload(self, submission_id: int) -> list[Finding]:
        """
        Test upload SVG dengan XSS payload.
        SVG adalah format XML yang dapat mengandung JavaScript — jika dirender di browser,
        payload akan dieksekusi.
        """
        findings = []
        resp = self._upload_file(
            submission_id,
            filename="figure1.svg",
            content=SVG_XSS_CONTENT,
            mime_type="image/svg+xml",
        )

        if resp and resp.status_code in (200, 201):
            try:
                data = resp.json()
                file_url = data.get("url") or data.get("path")

                if data.get("fileStage") or data.get("id"):
                    findings.append(Finding(
                        title="File Upload: SVG dengan XSS Payload Diterima",
                        severity="high",
                        description=(
                            "Server OJS menerima upload file SVG yang mengandung event handler JavaScript "
                            "(onload=\"...\"). Jika file ini dapat diakses via browser secara langsung "
                            "(bukan sebagai download), JavaScript akan dieksekusi di konteks domain OJS — "
                            "ini adalah Stored XSS via file upload."
                        ),
                        evidence=(
                            f"Upload 'figure1.svg' dengan payload onload berhasil (HTTP {resp.status_code}). "
                            f"File URL: {file_url}"
                        ),
                        module=self.name,
                        remediation=(
                            "Jangan izinkan upload SVG atau sanitasi konten SVG sebelum disimpan. "
                            "Gunakan library sanitasi SVG yang aman (misal: DOMPurify untuk SVG). "
                            "Set Content-Disposition: attachment untuk file SVG sehingga browser "
                            "mendownload, bukan menampilkan langsung."
                        ),
                        url=f"{self.target_url}/api/v1/submissions/{submission_id}/files",
                        extra={"cwe_id": "CWE-79", "submission_id": submission_id},
                    ))
            except (ValueError, KeyError):
                pass

        return findings

    def _check_direct_upload_endpoints(self) -> list[Finding]:
        """
        Jika tidak ada submission aktif, test endpoint upload generik OJS
        yang mungkin tidak memvalidasi dengan benar.
        """
        findings = []
        upload_endpoints = [
            f"{self.target_url}/index.php/index/management/uploadPublicFile",
            f"{self.target_url}/index.php/index/api/v1/temporaryFiles",
        ]

        for url in upload_endpoints:
            try:
                files = {"file": ("test.php", io.BytesIO(PHP_CONTENT), "application/pdf")}
                resp = self.session.post(url, files=files, timeout=self.REQUEST_TIMEOUT)

                if resp.status_code in (200, 201):
                    try:
                        data = resp.json()
                        if data.get("id") or data.get("url"):
                            findings.append(Finding(
                                title="File Upload Endpoint Rentan: PHP Diterima",
                                severity="high",
                                description=(
                                    f"Endpoint upload '{url}' menerima file PHP tanpa validasi ekstensi. "
                                    "Endpoint ini bisa dieksploitasi untuk Remote Code Execution."
                                ),
                                evidence=f"POST {url} dengan file .php → HTTP {resp.status_code}",
                                module=self.name,
                                remediation=(
                                    "Tambahkan validasi ekstensi file dan MIME type yang ketat "
                                    "di semua endpoint upload."
                                ),
                                url=url,
                                extra={"cwe_id": "CWE-434"},
                            ))
                            break
                    except (ValueError, KeyError):
                        pass

            except requests.RequestException:
                continue

        return findings
