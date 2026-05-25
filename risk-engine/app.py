
from flask import Flask, request, jsonify
from pymongo import MongoClient
import os
from risk_utils import calculate_cvss_score, get_cwe_info, get_risk_level


app = Flask(__name__)

# Setup MongoDB connection
mongo_host = os.environ.get("DATABASE_HOST", "localhost")
mongo_port = 27017
mongo_db = os.environ.get("DATABASE_NAME", "appdb")
client = MongoClient(f"mongodb://{mongo_host}:{mongo_port}/")
db = client[mongo_db]
results_collection = db["risk_results"]

@app.route("/", methods=["GET"])
def health_check():
    return jsonify({"status": "Risk Engine is Running", "role": "Data Parser & Classifier"})


@app.route("/analyze", methods=["POST"])
def analyze_scan_results():
    raw_findings = request.json
    if not raw_findings or not isinstance(raw_findings, list):
        return jsonify({"error": "Format data harus berupa List JSON"}), 400

    processed_results = []
    max_score = 0.0

    for item in raw_findings:
        name = item.get("name", "Unknown Vulnerability")
        vector = item.get("cvss_vector", "")
        cwe_id = item.get("cwe_id", "N/A")
        evidence = item.get("extracted_results", "No evidence found")
        score = item.get("base_score")
        if not score and vector:
            score = calculate_cvss_score(vector)
        elif not score:
            score = 0.0
        category = get_cwe_info(cwe_id)
        severity = get_risk_level(score)
        finding = {
            "vulnerability_name": name,
            "cwe_id": cwe_id,
            "category": category,
            "cvss_score": score,
            "cvss_vector": vector,
            "severity": severity,
            "evidence": evidence
        }
        processed_results.append(finding)
        if score > max_score:
            max_score = score
    final_response = {
        "summary": {
            "total_findings": len(processed_results),
            "overall_max_score": max_score,
            "overall_severity": get_risk_level(max_score)
        },
        "details": processed_results
    }
    # Simpan ke database agar bisa diakses dashboard
    results_collection.insert_one(final_response)
    return jsonify(final_response)

# Endpoint untuk dashboard mengambil semua hasil risk engine
@app.route("/results", methods=["GET"])
def get_results():
    results = list(results_collection.find({}, {"_id": 0}))
    return jsonify(results)

# Endpoint untuk dashboard mengambil hasil berdasarkan CWE ID
@app.route("/results/<cwe_id>", methods=["GET"])
def get_result_by_cwe(cwe_id):
    results = list(results_collection.find({"details.cwe_id": cwe_id}, {"_id": 0}))
    if results:
        return jsonify(results)
    else:
        return jsonify({"error": "Result not found"}), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)