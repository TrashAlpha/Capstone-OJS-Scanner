"""
scanners/orchestrator.py
Koordinator semua scanner module — external maupun internal.

External modules (execute_all):
    Tidak butuh autentikasi. Dipanggil bersamaan dengan Nuclei scan.

Internal modules (execute_internal):
    Butuh session requests.Session yang sudah login ke OJS.
    Dipanggil dari endpoint /scan/internal.
"""

from scanners.external.version_scan import VersionScanner
from scanners.external.security_headers import SecurityHeadersScanner
from scanners.external.dir_fuzzing import DirFuzzingScanner
from scanners.external.public_injection import PublicInjectionScanner

from scanners.internal.security_audit import SecurityAuditScanner
from scanners.internal.broken_access import BrokenAccessScanner
from scanners.internal.idor import IDORScanner
from scanners.internal.param_injection import ParamInjectionScanner
from scanners.internal.file_upload import FileUploadScanner


class ScanOrchestrator:
    def __init__(self, target_url: str):
        self.target_url = target_url

    def execute_all(self) -> list[dict]:
        """
        Jalankan semua modul external scanner (unauthenticated).
        Dipanggil bersamaan dengan Nuclei scan dari routes.py.
        """
        modules = [
            VersionScanner(self.target_url),
            SecurityHeadersScanner(self.target_url),
            DirFuzzingScanner(self.target_url),
            PublicInjectionScanner(self.target_url),
        ]

        return [self._run_module_safe(m) for m in modules]

    def execute_internal(self, session) -> list[dict]:
        """
        Jalankan semua modul internal scanner (authenticated).
        Membutuhkan session requests.Session yang sudah login ke OJS.
        """
        modules = [
            SecurityAuditScanner(self.target_url, session=session),
            BrokenAccessScanner(self.target_url, session=session),
            IDORScanner(self.target_url, session=session),
            ParamInjectionScanner(self.target_url, session=session),
            FileUploadScanner(self.target_url, session=session),
        ]

        return [self._run_module_safe(m) for m in modules]

    def _run_module_safe(self, module) -> dict:
        """
        Jalankan satu module dengan error isolation.
        Jika module crash, kembalikan hasil kosong dengan error finding
        agar module lain tetap bisa berjalan.
        """
        try:
            return module.run()
        except Exception as e:
            return {
                "module": getattr(module, "name", type(module).__name__),
                "findings": [{
                    "title": f"Module Error: {type(module).__name__}",
                    "severity": "info",
                    "description": f"Modul scanner mengalami error dan tidak bisa dijalankan.",
                    "evidence": str(e),
                    "module": getattr(module, "name", "unknown"),
                    "cve": None,
                    "remediation": None,
                    "url": self.target_url,
                    "extra": {"error": str(e)},
                }],
                "raw": {"error": str(e)},
            }
