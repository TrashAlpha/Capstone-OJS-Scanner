from scanners.external.version_scan import VersionScanner
from scanners.external.security_headers import SecurityHeadersScanner

class ScanOrchestrator:
    def __init__(self, target_url):
        self.target_url = target_url

    def execute_all(self):
        modules = [
            VersionScanner(self.target_url),
            SecurityHeadersScanner(self.target_url),
            # modul berikutnya ditambah di sini
        ]

        all_results = []
        for module in modules:
            all_results.append(module.run())

        return all_results