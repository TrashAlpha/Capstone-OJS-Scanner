from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from risk_utils import calculate_cvss_score, get_cwe_info, get_risk_level
from typing import List

app = FastAPI()

# Variabel global untuk menyimpan hasil scan terakhir (in-memory)
stored_results = []

@app.get("/")
def health_check():
    return {"message": "Risk Engine API is active"}

@app.post("/analyze")
def analyze(data: List[dict]):
    global stored_results
    current_scan = []
    for item in data:
        score = calculate_cvss_score(item.get("cvss_vector", ""))
        processed = {
            "title": item.get("name"),
            "cvss": score,
            "severity": get_risk_level(score),
            "category": get_cwe_info(item.get("cwe_id")),
            "evidence": item.get("extracted_results")
        }
        current_scan.append(processed)
    stored_results.clear()
    stored_results.extend(current_scan)
    return {"status": "Analysis Complete", "count": len(current_scan)}

@app.get("/api/v1/results")
def get_results_for_dashboard():
    if not stored_results:
        return JSONResponse(status_code=404, content={"message": "No scan data available yet"})
    return {
        "status": "success",
        "total_vulnerabilities": len(stored_results),
        "data": stored_results
    }
