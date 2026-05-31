"""
risk_utils.py
Utility functions untuk kalkulasi CVSS dan klasifikasi risiko.
"""

from cvss import CVSS3


def calculate_cvss_score(vector_string):
    """
    Fungsi Kalkulator: Mengubah CVSS Vector menjadi skor numerik.
    Contoh Input: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    """
    try:
        c = CVSS3(vector_string)
        return c.scores()[0]  # Base Score
    except Exception:
        return 0.0


def get_cwe_info(cwe_id):
    """
    Mapping CWE ID ke kategori yang mudah dibaca untuk Dashboard.
    Sudah mencakup CWE yang relevan untuk OJS CVE.
    """
    cwe_map = {
        # ── OJS-specific CWEs ──────────────────────────────────
        "CWE-611": "XML External Entity (XXE)",
        "CWE-79": "Cross-site Scripting (XSS)",
        "CWE-352": "Cross-Site Request Forgery (CSRF)",

        # ── General CWEs ──────────────────────────────────────
        "CWE-89": "SQL Injection",
        "CWE-22": "Path Traversal",
        "CWE-434": "Unrestricted File Upload",
        "CWE-639": "Insecure Direct Object Reference (IDOR)",
        "CWE-200": "Information Exposure",
        "CWE-284": "Improper Access Control",
        "CWE-287": "Improper Authentication",
        "CWE-306": "Missing Authentication for Critical Function",
        "CWE-502": "Deserialization of Untrusted Data",
        "CWE-918": "Server-Side Request Forgery (SSRF)",
        "CWE-78": "OS Command Injection",
        "CWE-94": "Code Injection",
        "CWE-116": "Improper Encoding or Escaping of Output",
        "CWE-269": "Improper Privilege Management",
        "CWE-538": "Insertion of Sensitive Information into Externally-Accessible File",
        "CWE-548": "Exposure of Information Through Directory Listing",
    }
    if isinstance(cwe_id, list):
        cwe_id = cwe_id[0] if cwe_id else "N/A"
    return cwe_map.get(str(cwe_id), "General Security Weakness")


def get_risk_level(score):
    """
    Klasifikasi risiko berdasarkan skor CVSS standar (CVSS v3.1).
    https://www.first.org/cvss/specification-document

    9.0 - 10.0  → CRITICAL
    7.0 - 8.9   → HIGH
    4.0 - 6.9   → MEDIUM
    0.1 - 3.9   → LOW
    0.0          → INFORMATIONAL
    """
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFORMATIONAL"