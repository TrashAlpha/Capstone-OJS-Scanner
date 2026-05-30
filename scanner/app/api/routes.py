"""
app/api/routes.py
Flask Blueprint dengan REST API endpoints untuk scanner service.
"""

import os
import time
import requests as http_requests
from flask import Blueprint, jsonify, request
from app.services.nuclei_service import NucleiService
from app.services.llm_service import LLMService
from app.services.report_service import ReportService
from app.utils.parser import findings_to_risk_engine_format
from app.config import logger

RISK_ENGINE_URL = os.getenv("RISK_ENGINE_URL", "http://risk-engine:5000")

# Lazy import database (mungkin belum ready saat startup)
try:
    from database.models import ScanLog
    DB_AVAILABLE = True
except Exception:
    DB_AVAILABLE = False

scanner_bp = Blueprint("scanner", __name__)

# ── Service instances ──────────────────────────────────────────
nuclei_service = NucleiService()
llm_service = LLMService()
report_service = ReportService()


# ═══════════════════════════════════════════════════════════════
# GET /  — Health check
# ═══════════════════════════════════════════════════════════════
@scanner_bp.route("/", methods=["GET"])
def health_check():
    return jsonify({
        "status": "Scanner Service Running",
        "engine": "Nuclei + Gemini 3.5 Flash",
        "version": "2.0.0",
    })


# ═══════════════════════════════════════════════════════════════
# POST /scan  — Full scan (Nuclei + LLM Analysis)
# ═══════════════════════════════════════════════════════════════
@scanner_bp.route("/scan", methods=["POST"])
def scan_full():
    """
    Jalankan full scan: Nuclei → LLM Analysis → Final Report.

    Request body:
    {
        "target_url": "http://target-ojs.com",
        "scan_type": "full",                     (optional, default: "full")
        "templates": ["all"]                     (optional, default: semua)
    }
    """
    payload = request.get_json(silent=True) or {}
    target_url = str(payload.get("target_url", "")).strip()
    scan_type = str(payload.get("scan_type", "full")).strip().lower()
    templates = payload.get("templates", None)

    # ── Validasi input ─────────────────────────────────────────
    if not target_url:
        return jsonify({"error": "target_url is required"}), 400

    if not nuclei_service.validate_target(target_url):
        return jsonify({"error": "target_url tidak valid. Gunakan http:// atau https://"}), 400

    # ── Log scan ke database ───────────────────────────────────
    scan_id = None
    if DB_AVAILABLE:
        try:
            scan_id = ScanLog.create(target_url, scan_type)
        except Exception as e:
            logger.warning(f"Failed to log scan start: {e}")

    start_time = time.time()

    try:
        # ── Step 1: Jalankan Nuclei scan ───────────────────────
        logger.info(f"Starting full scan on {target_url}")
        nuclei_results = nuclei_service.run_scan(target_url, templates)

        # ── Step 2: LLM Analysis ──────────────────────────────
        llm_analysis = {}
        if scan_type != "nuclei_only":
            findings = nuclei_results.get("findings", [])
            llm_analysis = llm_service.analyze(findings)

        # ── Step 3: Generate report ────────────────────────────
        scan_duration = time.time() - start_time

        if scan_type == "nuclei_only":
            report = report_service.generate_nuclei_only(
                target_url, nuclei_results, scan_duration
            )
        else:
            report = report_service.generate(
                target_url, scan_type, nuclei_results, llm_analysis, scan_duration
            )

        # ── Update database ────────────────────────────────────
        if DB_AVAILABLE and scan_id:
            try:
                ScanLog.update_completed(scan_id, report)
            except Exception as e:
                logger.warning(f"Failed to log scan completion: {e}")

        report["scan_id"] = scan_id

        # ── Step 4: Forward ke Risk Engine ─────────────────────
        risk_response = _forward_to_risk_engine(
            target_url, scan_id, nuclei_results.get("findings", [])
        )
        if risk_response:
            report["risk_engine"] = risk_response

        return jsonify(report)

    except Exception as e:
        scan_duration = time.time() - start_time
        logger.error(f"Scan failed: {e}")

        # Update database dengan error
        if DB_AVAILABLE and scan_id:
            try:
                ScanLog.update_failed(scan_id, str(e))
            except Exception:
                pass

        return jsonify({
            "error": f"Scan gagal: {str(e)}",
            "scan_id": scan_id,
            "scan_duration_seconds": round(scan_duration, 2),
        }), 500


# ═══════════════════════════════════════════════════════════════
# POST /scan/nuclei  — Nuclei scan only (tanpa LLM)
# ═══════════════════════════════════════════════════════════════
@scanner_bp.route("/scan/nuclei", methods=["POST"])
def scan_nuclei_only():
    """
    Jalankan Nuclei scan saja tanpa LLM analysis.
    Lebih cepat, cocok untuk quick check.
    """
    payload = request.get_json(silent=True) or {}
    target_url = str(payload.get("target_url", "")).strip()
    templates = payload.get("templates", None)

    if not target_url:
        return jsonify({"error": "target_url is required"}), 400

    if not nuclei_service.validate_target(target_url):
        return jsonify({"error": "target_url tidak valid"}), 400

    # Log ke database
    scan_id = None
    if DB_AVAILABLE:
        try:
            scan_id = ScanLog.create(target_url, "nuclei_only")
        except Exception as e:
            logger.warning(f"Failed to log scan: {e}")

    start_time = time.time()

    try:
        nuclei_results = nuclei_service.run_scan(target_url, templates)
        scan_duration = time.time() - start_time

        report = report_service.generate_nuclei_only(
            target_url, nuclei_results, scan_duration
        )

        if DB_AVAILABLE and scan_id:
            try:
                ScanLog.update_completed(scan_id, report)
            except Exception:
                pass

        report["scan_id"] = scan_id

        # ── Forward ke Risk Engine ─────────────────────────────
        risk_response = _forward_to_risk_engine(
            target_url, scan_id, nuclei_results.get("findings", [])
        )
        if risk_response:
            report["risk_engine"] = risk_response

        return jsonify(report)

    except Exception as e:
        if DB_AVAILABLE and scan_id:
            try:
                ScanLog.update_failed(scan_id, str(e))
            except Exception:
                pass

        return jsonify({"error": str(e), "scan_id": scan_id}), 500


# ═══════════════════════════════════════════════════════════════
# GET /templates  — List available templates
# ═══════════════════════════════════════════════════════════════
@scanner_bp.route("/templates", methods=["GET"])
def list_templates():
    """List semua Nuclei templates OJS yang tersedia."""
    templates = nuclei_service.list_templates()
    return jsonify({
        "total": len(templates),
        "templates": templates,
    })


# ═══════════════════════════════════════════════════════════════
# GET /scans  — Scan history
# ═══════════════════════════════════════════════════════════════
@scanner_bp.route("/scans", methods=["GET"])
def scan_history():
    """Ambil riwayat scan terbaru."""
    if not DB_AVAILABLE:
        return jsonify({"error": "Database tidak tersedia"}), 503

    limit = request.args.get("limit", 20, type=int)
    limit = min(limit, 100)  # Max 100

    try:
        logs = ScanLog.get_recent(limit)
        # Konversi datetime ke string untuk JSON serialization
        for log in logs:
            for key in ["created_at", "completed_at"]:
                if log.get(key) and hasattr(log[key], "isoformat"):
                    log[key] = log[key].isoformat()

        return jsonify({
            "total": len(logs),
            "scans": logs,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════
# GET /scans/<id>  — Detail scan by ID
# ═══════════════════════════════════════════════════════════════
@scanner_bp.route("/scans/<int:scan_id>", methods=["GET"])
def scan_detail(scan_id):
    """Ambil detail scan berdasarkan ID."""
    if not DB_AVAILABLE:
        return jsonify({"error": "Database tidak tersedia"}), 503

    try:
        log = ScanLog.get_by_id(scan_id)
        if not log:
            return jsonify({"error": "Scan not found"}), 404

        # Konversi datetime
        for key in ["created_at", "completed_at"]:
            if log.get(key) and hasattr(log[key], "isoformat"):
                log[key] = log[key].isoformat()

        return jsonify(log)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════
# Helper: Forward findings ke Risk Engine
# ═══════════════════════════════════════════════════════════════
def _forward_to_risk_engine(target_url, scan_id, findings):
    """
    Kirim findings ke Risk Engine untuk scoring & klasifikasi.
    Dipanggil otomatis setelah setiap scan selesai.

    Returns:
        dict response dari Risk Engine, atau None jika gagal
    """
    if not findings:
        logger.info("No findings to forward to Risk Engine")
        return None

    # Format findings sesuai yang diharapkan Risk Engine
    risk_findings = findings_to_risk_engine_format(findings)

    payload = {
        "target_url": target_url,
        "scan_id": scan_id,
        "findings": risk_findings,
    }

    try:
        url = f"{RISK_ENGINE_URL}/analyze"
        logger.info(f"Forwarding {len(risk_findings)} findings to Risk Engine: {url}")

        response = http_requests.post(
            url,
            json=payload,
            timeout=30,
        )

        if response.status_code == 200:
            result = response.json()
            logger.info(
                f"Risk Engine response: severity={result.get('summary', {}).get('overall_severity', 'N/A')}, "
                f"telegram_notified={result.get('telegram_notified', False)}"
            )
            return result
        else:
            logger.error(f"Risk Engine error: {response.status_code} - {response.text}")
            return None

    except http_requests.exceptions.ConnectionError:
        logger.warning("Risk Engine not reachable, skipping forward")
        return None
    except Exception as e:
        logger.error(f"Failed to forward to Risk Engine: {e}")
        return None
