from flask import Flask, request, jsonify
from risk_utils import calculate_cvss_score, get_cwe_info, get_risk_level

app = Flask(__name__)

@app.route("/", methods=["GET"])
def health_check():
    return jsonify({"status": "Risk Engine is Running", "role": "Data Parser & Classifier"})

@app.route("/analyze", methods=["POST"])
def analyze_scan_results():
    # Menerima file JSON hasil scan dari Orang 2 atau Orang 3
    raw_findings = request.json
    
    if not raw_findings or not isinstance(raw_findings, list):
        return jsonify({"error": "Format data harus berupa List JSON"}), 400

    processed_results = []
    max_score = 0.0

    for item in raw_findings:
        # 1. Ambil data dari scanner temanmu
        name = item.get("name", "Unknown Vulnerability")
        vector = item.get("cvss_vector", "")
        cwe_id = item.get("cwe_id", "N/A")
        evidence = item.get("extracted_results", "No evidence found")

        # 2. Hitung skor otomatis (Kalkulator CVSS)
        # Jika scanner sudah kasih skor, pakai itu. Jika tidak, hitung dari vektor.
        score = item.get("base_score")
        if not score and vector:
            score = calculate_cvss_score(vector)
        elif not score:
            score = 0.0

        # 3. Dapatkan Kategori dan Level Risiko
        category = get_cwe_info(cwe_id)
        severity = get_risk_level(score)

        # 4. Simpan hasil yang sudah rapi
        processed_results.append({
            "vulnerability_name": name,
            "cwe_id": cwe_id,
            "category": category,
            "cvss_score": score,
            "cvss_vector": vector,
            "severity": severity,
            "evidence": evidence
        })

        if score > max_score:
            max_score = score

    # Response final yang akan dibaca oleh Dashboard Laravel
    final_response = {
        "summary": {
            "total_findings": len(processed_results),
            "overall_max_score": max_score,
            "overall_severity": get_risk_level(max_score)
        },
        "details": processed_results
    }

    return jsonify(final_response)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)