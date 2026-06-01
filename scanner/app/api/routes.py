"""
app/api/routes.py
Flask Blueprint dengan REST API endpoints untuk scanner service.
"""

import os
import time
import threading
from datetime import datetime, timezone
import requests as http_requests
from flask import Blueprint, jsonify, request
from app.services.nuclei_service import NucleiService
from app.services.llm_service import LLMService
from app.services.report_service import ReportService
from app.services.auth_service import OJSAuthService
from app.utils.parser import findings_to_risk_engine_format, python_findings_to_risk_engine_format
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
auth_service = OJSAuthService()


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
    scan_profile = str(payload.get("scan_profile", "general")).strip().lower()
    scan_type = "external"

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

    # ── Mulai Background Job ───────────────────────────────────
    thread = threading.Thread(
        target=_background_scan_task,
        args=(scan_id, target_url, scan_type, scan_profile)
    )
    thread.daemon = True
    thread.start()

    return jsonify({
        "message": "Scan started in background",
        "scan_id": scan_id,
        "target_url": target_url,
        "scan_profile": scan_profile,
        "status": "running"
    }), 202



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
    scan_profile = str(payload.get("scan_profile", "general")).strip().lower()

    if not target_url:
        return jsonify({"error": "target_url is required"}), 400

    if not nuclei_service.validate_target(target_url):
        return jsonify({"error": "target_url tidak valid"}), 400

    # Log ke database
    scan_id = None
    if DB_AVAILABLE:
        try:
            scan_id = ScanLog.create(target_url, "external_nuclei")
        except Exception as e:
            logger.warning(f"Failed to log scan: {e}")

    thread = threading.Thread(
        target=_background_scan_task,
        args=(scan_id, target_url, "external_nuclei", scan_profile)
    )
    thread.daemon = True
    thread.start()

    return jsonify({
        "message": "Nuclei scan started in background",
        "scan_id": scan_id,
        "target_url": target_url,
        "scan_profile": scan_profile,
        "status": "running"
    }), 202


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
# POST /scan/full  — Full scan (External + Internal, satu record)
# ═══════════════════════════════════════════════════════════════
@scanner_bp.route("/scan/full", methods=["POST"])
def scan_full_combined():
    """
    Jalankan Full scan: External (Nuclei + LLM) + Internal (authenticated) dalam satu DB record.

    Request body:
    {
        "target_url": "http://target-ojs.com",
        "username": "admin",
        "password": "secret",
        "scan_profile": "general"   (optional)
    }
    """
    payload = request.get_json(silent=True) or {}
    target_url = str(payload.get("target_url", "")).strip()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()
    scan_profile = str(payload.get("scan_profile", "general")).strip().lower()

    if not target_url:
        return jsonify({"error": "target_url is required"}), 400
    if not nuclei_service.validate_target(target_url):
        return jsonify({"error": "target_url tidak valid"}), 400
    if not username or not password:
        return jsonify({"error": "username dan password diperlukan untuk Full Scan"}), 400

    # Verifikasi login sebelum masuk background thread
    session = auth_service.login(target_url, username, password)
    if not session:
        return jsonify({
            "error": "Login gagal — periksa username/password dan pastikan target OJS bisa diakses"
        }), 401

    role = auth_service.get_role(session, target_url)
    logger.info(f"[FullScan] Login berhasil sebagai '{role}' di {target_url}")

    scan_id = None
    if DB_AVAILABLE:
        try:
            scan_id = ScanLog.create(target_url, "full")
        except Exception as e:
            logger.warning(f"Failed to log full scan start: {e}")

    thread = threading.Thread(
        target=_background_full_scan_task,
        args=(scan_id, target_url, scan_profile, session, role),
    )
    thread.daemon = True
    thread.start()

    return jsonify({
        "message": "Full scan started in background",
        "scan_id": scan_id,
        "target_url": target_url,
        "authenticated_role": role,
        "status": "running",
    }), 202


# ═══════════════════════════════════════════════════════════════
# POST /scan/auth-test  — Verifikasi kredensial OJS
# ═══════════════════════════════════════════════════════════════
@scanner_bp.route("/scan/auth-test", methods=["POST"])
def scan_auth_test():
    """
    Verifikasi apakah kredensial OJS valid tanpa menjalankan full scan.
    Synchronous, max 15 detik.

    Request body:
    {
        "target_url": "http://target-ojs.com",
        "username": "admin",
        "password": "secret"
    }
    """
    payload = request.get_json(silent=True) or {}
    target_url = str(payload.get("target_url", "")).strip()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()

    if not target_url:
        return jsonify({"error": "target_url is required"}), 400
    if not nuclei_service.validate_target(target_url):
        return jsonify({"error": "target_url tidak valid"}), 400
    if not username or not password:
        return jsonify({"error": "username dan password diperlukan"}), 400

    session = auth_service.login(target_url, username, password)
    if not session:
        return jsonify({
            "valid": False,
            "role": None,
            "message": "Login gagal — periksa username/password dan pastikan target OJS bisa diakses",
        }), 401

    role = auth_service.get_role(session, target_url)
    return jsonify({
        "valid": True,
        "role": role,
        "message": f"Login berhasil sebagai '{role}'",
    })


# ═══════════════════════════════════════════════════════════════
# POST /scan/internal  — Authenticated internal scan
# ═══════════════════════════════════════════════════════════════
@scanner_bp.route("/scan/internal", methods=["POST"])
def scan_internal():
    """
    Jalankan internal scan (authenticated) dengan kredensial admin OJS.
    Menggunakan Python scanner modules (bukan Nuclei).

    Request body:
    {
        "target_url": "http://target-ojs.com",
        "username": "admin",
        "password": "secret"
    }
    """
    payload = request.get_json(silent=True) or {}
    target_url = str(payload.get("target_url", "")).strip()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()

    if not target_url:
        return jsonify({"error": "target_url is required"}), 400
    if not nuclei_service.validate_target(target_url):
        return jsonify({"error": "target_url tidak valid"}), 400
    if not username or not password:
        return jsonify({"error": "username dan password diperlukan"}), 400

    # Verifikasi login sebelum mulai background task
    session = auth_service.login(target_url, username, password)
    if not session:
        return jsonify({
            "error": "Login gagal — periksa username/password dan pastikan target OJS bisa diakses"
        }), 401

    role = auth_service.get_role(session, target_url)
    logger.info(f"[InternalScan] Login berhasil sebagai '{role}' di {target_url}")

    # Log ke database
    scan_id = None
    if DB_AVAILABLE:
        try:
            scan_id = ScanLog.create(target_url, "internal")
        except Exception as e:
            logger.warning(f"Failed to log internal scan start: {e}")

    thread = threading.Thread(
        target=_background_internal_scan_task,
        args=(scan_id, target_url, session, role),
    )
    thread.daemon = True
    thread.start()

    return jsonify({
        "message": "Internal scan started in background",
        "scan_id": scan_id,
        "target_url": target_url,
        "authenticated_role": role,
        "status": "running",
    }), 202


# ═══════════════════════════════════════════════════════════════
# Helper: Post pre-formatted findings ke Risk Engine
# ═══════════════════════════════════════════════════════════════
def _post_to_risk_engine(target_url, scan_id, risk_findings):
    """
    Kirim findings yang sudah dalam format Risk Engine langsung ke /analyze.
    Digunakan oleh internal scanner yang mengkonversi findings sendiri.
    """
    if not risk_findings:
        logger.info("No findings to forward to Risk Engine")
        return None

    payload = {
        "target_url": target_url,
        "scan_id": scan_id,
        "findings": risk_findings,
    }

    try:
        url = f"{RISK_ENGINE_URL}/analyze"
        response = http_requests.post(url, json=payload, timeout=30)
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Risk Engine error: {response.status_code} - {response.text}")
            return None
    except http_requests.exceptions.ConnectionError:
        logger.warning("Risk Engine not reachable, skipping forward")
        return None
    except Exception as e:
        logger.error(f"Failed to forward to Risk Engine: {e}")
        return None


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

# ═══════════════════════════════════════════════════════════════
# Helper: Background Task Worker
# ═══════════════════════════════════════════════════════════════
def _background_scan_task(scan_id, target_url, scan_type, scan_profile):
    """Worker thread untuk menjalankan proses scan secara asinkronus."""
    start_time = time.time()
    
    try:
        logger.info(f"[Background] Starting {scan_type} scan on {target_url} (profile: {scan_profile})")
        
        # 1. Jalankan Nuclei
        nuclei_results = nuclei_service.run_scan(target_url, scan_profile)
        
        # 2. LLM Analysis (jika bukan nuclei_only)
        llm_analysis = {}
        if scan_type != "external_nuclei":
            findings = nuclei_results.get("findings", [])
            llm_analysis = llm_service.analyze(findings)

        # 3. Generate Report
        scan_duration = time.time() - start_time
        if scan_type == "external_nuclei":
            report = report_service.generate_nuclei_only(
                target_url, nuclei_results, scan_duration
            )
        else:
            report = report_service.generate(
                target_url, scan_type, nuclei_results, llm_analysis, scan_duration
            )
            
        # 4. Forward ke Risk Engine
        risk_response = _forward_to_risk_engine(
            target_url, scan_id, nuclei_results.get("findings", [])
        )
        if risk_response:
            report["risk_engine"] = risk_response
            
        # 5. Update Database
        if DB_AVAILABLE and scan_id:
            try:
                ScanLog.update_completed(scan_id, report)
            except Exception as e:
                logger.warning(f"Failed to log scan completion: {e}")
                
        logger.info(f"[Background] Scan completed successfully for {target_url} in {scan_duration:.2f}s")
        
    except Exception as e:
        scan_duration = time.time() - start_time
        logger.error(f"[Background] Scan failed for {target_url}: {e}")
        
        if DB_AVAILABLE and scan_id:
            try:
                ScanLog.update_failed(scan_id, str(e))
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════
# Helper: Background Task Worker — Full Scan (External + Internal)
# ═══════════════════════════════════════════════════════════════
def _background_full_scan_task(scan_id, target_url, scan_profile, session, role):
    """Worker thread untuk full scan: external (Nuclei+LLM) + internal dalam satu record."""
    from scanners.orchestrator import ScanOrchestrator

    start_time = time.time()

    try:
        logger.info(f"[Background/Full] Starting full scan on {target_url} (role: {role})")

        # 1. External scan (Nuclei)
        nuclei_results = nuclei_service.run_scan(target_url, scan_profile)
        external_findings = nuclei_results.get("findings", [])
        logger.info(f"[Background/Full] External scan: {len(external_findings)} findings")

        # 2. Internal scan (authenticated)
        orchestrator = ScanOrchestrator(target_url)
        module_results = orchestrator.execute_internal(session)
        internal_findings_raw = []
        for result in module_results:
            internal_findings_raw.extend(result.get("findings", []))
        logger.info(f"[Background/Full] Internal scan: {len(internal_findings_raw)} findings")

        # 3. LLM Analysis (external + internal masing-masing)
        llm_external = llm_service.analyze(external_findings)
        llm_internal = llm_service.analyze_internal(internal_findings_raw)

        # 4. Gabungkan severity counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        nuclei_stats = nuclei_results.get("stats", {}).get("by_severity", {})
        for k in severity_counts:
            severity_counts[k] += nuclei_stats.get(k, 0)
        for f in internal_findings_raw:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        scan_duration = time.time() - start_time

        report = {
            "target_url": target_url,
            "scan_type": "full",
            "authenticated_role": role,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_duration_seconds": round(scan_duration, 2),
            "summary": {
                "total_findings": len(external_findings) + len(internal_findings_raw),
                "findings_count": severity_counts,
                "external_findings_count": len(external_findings),
                "internal_findings_count": len(internal_findings_raw),
            },
            # llm_analysis di top-level digunakan oleh models.py untuk risk_assessment
            "llm_analysis": {
                "summary": llm_external.get("summary", ""),
                "risk_assessment": llm_external.get("risk_assessment", ""),
                "recommendations": llm_external.get("recommendations", []),
                "finding_analysis": llm_external.get("finding_analysis", []),
                "llm_failed": llm_external.get("llm_failed", False),
                "raw_response": llm_external.get("raw_response", ""),
            },
            "external": {
                "nuclei_results": external_findings,
                "llm_analysis": llm_external,
                "errors": nuclei_results.get("errors", []),
            },
            "internal": {
                "module_results": module_results,
                "findings": internal_findings_raw,
                "llm_analysis": llm_internal,
            },
            # Top-level aliases untuk backward compat dengan dashboard
            "nuclei_results": external_findings,
            "module_results": module_results,
            "warnings": nuclei_results.get("errors", []),
        }

        # 5. Forward external findings ke Risk Engine
        risk_response = _forward_to_risk_engine(target_url, scan_id, external_findings)
        if risk_response:
            report["risk_engine"] = risk_response

        # 6. Update satu DB record
        if DB_AVAILABLE and scan_id:
            try:
                ScanLog.update_completed(scan_id, report)
            except Exception as e:
                logger.warning(f"Failed to log full scan completion: {e}")

        logger.info(
            f"[Background/Full] Scan completed for {target_url} in {scan_duration:.2f}s "
            f"— {len(external_findings)} external + {len(internal_findings_raw)} internal findings"
        )

    except Exception as e:
        scan_duration = time.time() - start_time
        logger.error(f"[Background/Full] Scan failed for {target_url}: {e}")
        if DB_AVAILABLE and scan_id:
            try:
                ScanLog.update_failed(scan_id, str(e))
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════
# Helper: Background Task Worker — Internal Scan
# ═══════════════════════════════════════════════════════════════
def _background_internal_scan_task(scan_id, target_url, session, role):
    """Worker thread untuk internal (authenticated) scan."""
    from scanners.orchestrator import ScanOrchestrator

    start_time = time.time()

    try:
        logger.info(f"[Background/Internal] Starting internal scan on {target_url} (role: {role})")

        orchestrator = ScanOrchestrator(target_url)
        module_results = orchestrator.execute_internal(session)

        # Flatten semua findings dari semua modul
        all_findings_raw = []
        for result in module_results:
            all_findings_raw.extend(result.get("findings", []))

        scan_duration = time.time() - start_time

        # Konversi ke format Risk Engine
        risk_findings = python_findings_to_risk_engine_format(module_results)

        # Hitung ringkasan per severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings_raw:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # LLM Analysis untuk internal scan
        llm_analysis = llm_service.analyze_internal(all_findings_raw)

        report = {
            "target_url": target_url,
            "scan_type": "internal",
            "authenticated_role": role,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_duration_seconds": round(scan_duration, 2),
            "summary": {
                "total_findings": len(all_findings_raw),
                "findings_count": severity_counts,
            },
            "llm_analysis": {
                "summary": llm_analysis.get("summary", ""),
                "risk_assessment": llm_analysis.get("risk_assessment", ""),
                "recommendations": llm_analysis.get("recommendations", []),
                "finding_analysis": llm_analysis.get("finding_analysis", []),
                "llm_failed": llm_analysis.get("llm_failed", False),
                "raw_response": llm_analysis.get("raw_response", ""),
            },
            "module_results": module_results,
            "findings": all_findings_raw,
        }

        # Forward ke Risk Engine (gunakan helper yang terima pre-formatted findings)
        risk_response = _post_to_risk_engine(target_url, scan_id, risk_findings)
        if risk_response:
            report["risk_engine"] = risk_response

        # Update Database
        if DB_AVAILABLE and scan_id:
            try:
                ScanLog.update_completed(scan_id, report)
            except Exception as e:
                logger.warning(f"Failed to log internal scan completion: {e}")

        logger.info(
            f"[Background/Internal] Scan completed for {target_url} in {scan_duration:.2f}s "
            f"— {len(all_findings_raw)} findings"
        )

    except Exception as e:
        scan_duration = time.time() - start_time
        logger.error(f"[Background/Internal] Scan failed for {target_url}: {e}")

        if DB_AVAILABLE and scan_id:
            try:
                ScanLog.update_failed(scan_id, str(e))
            except Exception:
                pass
