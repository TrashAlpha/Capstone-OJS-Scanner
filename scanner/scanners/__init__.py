"""
scanners/
Python-based scanner modules untuk OJS Security Scanner.

Folder ini berisi modul scanner berbasis Python (requests library),
sebagai komplemen dari Nuclei YAML templates di app/templates/ojs/.

Struktur:
    external/   — Unauthenticated checks, tidak butuh login ke OJS.
                  Dijalankan bersamaan dengan Nuclei dari /scan dan /scan/nuclei.

    internal/   — Authenticated checks, butuh kredensial admin/editor OJS.
                  Dijalankan dari endpoint /scan/internal dengan session aktif.

Cara pakai dari Flask app (app/api/routes.py):
    from scanners.orchestrator import ScanOrchestrator
    orchestrator = ScanOrchestrator(target_url)
    results = orchestrator.execute_all()              # external modules
    results = orchestrator.execute_internal(session)  # internal modules (butuh login)

Setiap modul mengextend ScannerModule dari scanners.base dan menghasilkan
list Finding yang dinormalisasi ke format yang sama.
"""
