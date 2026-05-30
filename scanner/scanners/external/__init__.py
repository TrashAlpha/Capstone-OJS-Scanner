"""
scanners/external/
Modul scanner eksternal (unauthenticated) untuk OJS.

Modul di sini tidak memerlukan login ke OJS — hanya mengirim request
HTTP biasa ke endpoint publik target. Berjalan paralel dengan Nuclei.

Modul yang tersedia:
    VersionScanner       — Deteksi versi OJS + mapping CVE
    SecurityHeadersScanner — Audit HTTP security headers
    DirFuzzingScanner    — Fuzzing path/direktori sensitif OJS
    PublicInjectionScanner — Uji injection di form publik (login, register, search)
"""
