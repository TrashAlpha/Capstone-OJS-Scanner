"""
scanners/internal/
Modul scanner internal (authenticated) untuk OJS.

Modul di sini memerlukan sesi login aktif (requests.Session dengan cookie OJSID).
Dapatkan session via OJSAuthService.login() sebelum menjalankan modul ini.

Modul yang tersedia:
    SecurityAuditScanner  — Audit konfigurasi admin (upload types, password policy, dll.)
    BrokenAccessScanner   — Uji privilege escalation dan akses kontrol
    IDORScanner           — Deteksi Insecure Direct Object Reference
    ParamInjectionScanner — Uji SQL injection, XSS, SSTI pada endpoint authenticated
    FileUploadScanner     — Uji validasi file upload di sistem submission

Semua modul menerima session via constructor:
    scanner = BrokenAccessScanner(target_url, session=session)
    result = scanner.run()
"""
