from flask import Flask, jsonify, request
from scanners.orchestrator import ScanOrchestrator
from datetime import datetime, timezone

app = Flask(__name__)


@app.route("/", methods=["GET"])
def home():
    return {"message": "Scanner Service Running"}


@app.route("/scan", methods=["POST"])
def scan_target():
    payload = request.get_json(silent=True) or {}
    target_url = str(payload.get("target_url", "")).strip()
    scan_type = str(payload.get("scan_type", "external")).strip().lower() or "external"

    if not target_url:
        return jsonify({"error": "target_url is required"}), 400

    warnings = []
    if scan_type in {"internal", "full"}:
        warnings.append(
            "Current scanner API only runs external modules. Internal/full requests are temporarily executed as external scans."
        )

    orchestrator = ScanOrchestrator(target_url)
    results = orchestrator.execute_all()

    return jsonify(
        {
            "target_url": target_url,
            "scan_type": scan_type,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "warnings": warnings,
            "results": results,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
