"""
app.py
Risk Engine Service — Flask REST API.
Menerima findings dari Scanner, menghitung CVSS, menyimpan ke DB,
mengirim notifikasi Telegram jika CRITICAL, dan menyediakan API untuk Dashboard.
"""

import logging
from flask import Flask, request, jsonify
from risk_utils import calculate_cvss_score, get_cwe_info, get_risk_level
from db import init_db, save_risk_result, mark_notified, get_results, get_result_detail
from telegram_notifier import send_critical_alert

# ── Logging ────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("risk-engine")

app = Flask(__name__)


# ═══════════════════════════════════════════════════════════════
# GET /  — Health check
# ═══════════════════════════════════════════════════════════════
@app.route("/", methods=["GET"])
def health_check():
    return jsonify({
        "status": "Risk Engine is Running",
        "role": "CVSS Scoring, Classification, DB Storage, Telegram Alerts",
        "version": "2.0.0",
    })


# ═══════════════════════════════════════════════════════════════
# POST /analyze  — Terima findings, hitung risk, simpan, notify
# ═══════════════════════════════════════════════════════════════
@app.route("/analyze", methods=["POST"])
def analyze_scan_results():
    """
    Menerima findings dari Scanner, menghitung CVSS score,
    mengklasifikasikan severity, menyimpan ke database,
    dan mengirim Telegram alert jika ada CRITICAL.

    Request body:
    {
        "target_url": "http://ojs",
        "scan_id": 1,                          (opsional, dari scanner)
        "findings": [
            {
                "name": "OJS XXE Injection",
                "cvss_vector": "CVSS:3.1/AV:N/...",
                "cwe_id": "CWE-611",
                "extracted_results": "...",
                "base_score": 9.8
            }
        ]
    }
    """
    payload = request.get_json(silent=True)

    if not payload:
        return jsonify({"error": "Request body harus berupa JSON"}), 400

    # Support format lama (langsung list) dan format baru (object)
    if isinstance(payload, list):
        # Format lama: langsung list of findings
        raw_findings = payload
        target_url = "unknown"
        scan_id = None
    elif isinstance(payload, dict):
        raw_findings = payload.get("findings", [])
        target_url = payload.get("target_url", "unknown")
        scan_id = payload.get("scan_id", None)
    else:
        return jsonify({"error": "Format data tidak valid"}), 400

    if not raw_findings or not isinstance(raw_findings, list):
        return jsonify({"error": "findings harus berupa list"}), 400

    # ── Step 1: Hitung CVSS & klasifikasi ──────────────────────
    processed_results = []
    max_score = 0.0

    for item in raw_findings:
        name = item.get("name", "Unknown Vulnerability")
        vector = item.get("cvss_vector", "")
        cwe_id = item.get("cwe_id", "N/A")
        evidence = item.get("extracted_results", "No evidence found")

        # Hitung skor: pakai base_score jika ada, kalau tidak hitung dari vector
        score = item.get("base_score")
        if not score and vector:
            score = calculate_cvss_score(vector)
        elif not score:
            score = 0.0

        # Pastikan score adalah float
        try:
            score = float(score)
        except (ValueError, TypeError):
            score = 0.0

        category = get_cwe_info(cwe_id)
        severity = get_risk_level(score)

        processed_results.append({
            "vulnerability_name": name,
            "cwe_id": cwe_id,
            "category": category,
            "cvss_score": score,
            "cvss_vector": vector,
            "severity": severity,
            "evidence": evidence if isinstance(evidence, str) else str(evidence),
        })

        if score > max_score:
            max_score = score

    overall_severity = get_risk_level(max_score)

    summary = {
        "total_findings": len(processed_results),
        "overall_max_score": max_score,
        "overall_severity": overall_severity,
    }

    # ── Step 2: Simpan ke database ─────────────────────────────
    result_id = None
    try:
        result_id = save_risk_result(target_url, scan_id, processed_results, summary)
        logger.info(f"Risk result saved to DB: id={result_id}")
    except Exception as e:
        logger.error(f"Failed to save to DB: {e}")

    # ── Step 3: Kirim Telegram alert jika CRITICAL ─────────────
    telegram_sent = False
    if overall_severity == "CRITICAL":
        try:
            telegram_sent = send_critical_alert(
                target_url=target_url,
                findings=processed_results,
                max_score=max_score,
                overall_severity=overall_severity,
                result_id=result_id,
            )
            if telegram_sent and result_id:
                mark_notified(result_id)
                logger.info(f"Telegram alert sent and DB marked for result_id={result_id}")
        except Exception as e:
            logger.error(f"Telegram notification failed: {e}")

    # ── Step 4: Return response ────────────────────────────────
    final_response = {
        "risk_result_id": result_id,
        "summary": summary,
        "details": processed_results,
        "telegram_notified": telegram_sent,
    }

    return jsonify(final_response)


# ═══════════════════════════════════════════════════════════════
# GET /results  — Daftar risk results untuk Dashboard
# ═══════════════════════════════════════════════════════════════
@app.route("/results", methods=["GET"])
def list_results():
    """Ambil daftar risk assessment terbaru."""
    limit = request.args.get("limit", 20, type=int)
    limit = min(limit, 100)

    try:
        results = get_results(limit)
        return jsonify({
            "total": len(results),
            "results": results,
        })
    except Exception as e:
        logger.error(f"Failed to get results: {e}")
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════
# GET /results/<id>  — Detail risk result + findings
# ═══════════════════════════════════════════════════════════════
@app.route("/results/<int:result_id>", methods=["GET"])
def result_detail(result_id):
    """Ambil detail risk result beserta semua findings."""
    try:
        result = get_result_detail(result_id)
        if not result:
            return jsonify({"error": "Result not found"}), 404
        return jsonify(result)
    except Exception as e:
        logger.error(f"Failed to get result detail: {e}")
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════
# Startup
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    try:
        init_db()
        logger.info("Database initialized")
    except Exception as e:
        logger.warning(f"Database initialization skipped: {e}")

    logger.info("Risk Engine started")
    app.run(host="0.0.0.0", port=5000)