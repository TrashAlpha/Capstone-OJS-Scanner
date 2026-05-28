"""
telegram_notifier.py
Mengirim notifikasi ke Telegram saat ditemukan risiko CRITICAL.
Menggunakan Telegram Bot HTTP API langsung (tanpa library telegram-bot).
"""

import os
import logging
import requests

logger = logging.getLogger("risk-engine")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/sendMessage"


def send_critical_alert(target_url, findings, max_score, overall_severity, result_id=None):
    """
    Kirim alert ke Telegram untuk temuan CRITICAL.

    Args:
        target_url: URL target yang di-scan
        findings: list of finding dicts yang severity-nya CRITICAL
        max_score: CVSS score tertinggi
        overall_severity: overall severity label
        result_id: ID dari risk_results (opsional)

    Returns:
        True jika berhasil, False jika gagal
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("Telegram credentials not configured, skipping notification")
        return False

    # Filter hanya CRITICAL findings
    critical_findings = [f for f in findings if f.get("severity") == "CRITICAL"]

    if not critical_findings:
        return False

    # Susun pesan
    message_lines = [
        "🚨 *CRITICAL VULNERABILITY DETECTED* 🚨",
        "",
        f"🎯 *Target:* `{target_url}`",
        f"📊 *Max CVSS Score:* `{max_score}`",
        f"⚠️ *Overall Severity:* `{overall_severity}`",
        f"🔢 *Risk Result ID:* `{result_id or 'N/A'}`",
        "",
        f"📋 *Critical Findings ({len(critical_findings)}):*",
    ]

    for i, f in enumerate(critical_findings, 1):
        message_lines.append(
            f"\n{i}. *{f.get('vulnerability_name', 'Unknown')}*"
        )
        message_lines.append(f"   • CWE: `{f.get('cwe_id', 'N/A')}`")
        message_lines.append(f"   • CVSS: `{f.get('cvss_score', 0.0)}`")
        message_lines.append(f"   • Kategori: {f.get('category', '-')}")

    message_lines.extend([
        "",
        "🔧 *Tindakan:* Segera lakukan perbaikan pada sistem OJS.",
        "📖 Lihat detail lengkap di Dashboard.",
    ])

    message = "\n".join(message_lines)

    try:
        url = TELEGRAM_API_URL.format(token=TELEGRAM_BOT_TOKEN)
        response = requests.post(
            url,
            json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message,
                "parse_mode": "Markdown",
                "disable_web_page_preview": True,
            },
            timeout=10,
        )

        if response.status_code == 200:
            logger.info(f"Telegram alert sent for {target_url} (result_id={result_id})")
            return True
        else:
            logger.error(
                f"Telegram API error: {response.status_code} - {response.text}"
            )
            return False

    except Exception as e:
        logger.error(f"Failed to send Telegram notification: {e}")
        return False
