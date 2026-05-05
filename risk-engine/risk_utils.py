from cvss import CVSS3

def calculate_cvss_score(vector_string):
    """
    Fungsi Kalkulator: Mengubah CVSS Vector menjadi skor numerik.
    Contoh Input: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    """
    try:
        # Menghitung otomatis menggunakan standar CVSS v3.x
        c = CVSS3(vector_string)
        return c.scores()[0]  # Mengambil Base Score
    except Exception:
        # Jika vektor tidak valid, berikan skor 0.0
        return 0.0

def get_cwe_info(cwe_id):
    """
    Mapping CWE ID ke kategori yang mudah dibaca untuk Dashboard.
    """
    cwe_map = {
        "CWE-79": "Cross-site Scripting (XSS)",
        "CWE-89": "SQL Injection",
        "CWE-22": "Path Traversal",
        "CWE-434": "Unrestricted File Upload",
        "CWE-639": "Insecure Direct Object Reference (IDOR)",
        "CWE-200": "Information Exposure",
        "CWE-284": "Improper Access Control"
    }
    return cwe_map.get(cwe_id, "General Security Weakness")

def get_risk_level(score):
    """
    Klasifikasi risiko berdasarkan skor CVSS standar.
    """
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0: return "LOW"
    return "INFORMATIONAL"