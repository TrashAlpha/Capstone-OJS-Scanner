"""
db.py
Database layer untuk Risk Engine.
Koneksi ke MySQL dan CRUD untuk risk_results & risk_findings.
"""

import json
import time
import os
import logging
import mysql.connector
from mysql.connector import pooling

logger = logging.getLogger("risk-engine")

# ── Database config dari environment ───────────────────────────
DATABASE_HOST = os.getenv("DATABASE_HOST", "app-db")
DATABASE_PORT = int(os.getenv("DATABASE_PORT", "3306"))
DATABASE_NAME = os.getenv("DATABASE_NAME", "appdb")
DATABASE_USER = os.getenv("DATABASE_USER", "appuser")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD", "app123")

_pool = None


def get_pool():
    """Lazy initialization connection pool."""
    global _pool
    if _pool is None:
        _pool = pooling.MySQLConnectionPool(
            pool_name="risk_pool",
            pool_size=3,
            pool_reset_session=True,
            host=DATABASE_HOST,
            port=DATABASE_PORT,
            database=DATABASE_NAME,
            user=DATABASE_USER,
            password=DATABASE_PASSWORD,
            charset="utf8mb4",
            collation="utf8mb4_unicode_ci",
            connect_timeout=10,
        )
        logger.info(f"DB pool initialized: {DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_NAME}")
    return _pool


def get_connection():
    """Ambil koneksi dari pool."""
    return get_pool().get_connection()


def init_db():
    """Inisialisasi tabel database dengan retry."""
    max_retries = 5
    for attempt in range(max_retries):
        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor()

            # Tabel risk_results: satu record per scan
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS risk_results (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    scan_id INT DEFAULT NULL,
                    target_url VARCHAR(500) NOT NULL,
                    total_findings INT DEFAULT 0,
                    max_cvss_score FLOAT DEFAULT 0.0,
                    overall_severity VARCHAR(20) DEFAULT 'INFORMATIONAL',
                    critical_count INT DEFAULT 0,
                    high_count INT DEFAULT 0,
                    medium_count INT DEFAULT 0,
                    low_count INT DEFAULT 0,
                    info_count INT DEFAULT 0,
                    telegram_notified BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_target_url (target_url(255)),
                    INDEX idx_severity (overall_severity),
                    INDEX idx_created_at (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)

            # Tabel risk_findings: detail per vulnerability
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS risk_findings (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    risk_result_id INT NOT NULL,
                    vulnerability_name VARCHAR(500) NOT NULL,
                    cwe_id VARCHAR(20) DEFAULT 'N/A',
                    category VARCHAR(200) DEFAULT 'General Security Weakness',
                    cvss_score FLOAT DEFAULT 0.0,
                    cvss_vector VARCHAR(200) DEFAULT '',
                    severity VARCHAR(20) DEFAULT 'INFORMATIONAL',
                    evidence TEXT DEFAULT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (risk_result_id) REFERENCES risk_results(id) ON DELETE CASCADE,
                    INDEX idx_risk_result (risk_result_id),
                    INDEX idx_severity (severity)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)

            conn.commit()
            logger.info("Database tables initialized successfully")
            return

        except Exception as e:
            logger.warning(f"DB init attempt {attempt+1}/{max_retries} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(3)
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    logger.error("Database initialization failed after all retries")


def save_risk_result(target_url, scan_id, findings_data, summary_data):
    """
    Simpan hasil risk assessment ke database.

    Args:
        target_url: URL target scan
        scan_id: ID scan dari scanner (bisa None)
        findings_data: list of processed finding dicts
        summary_data: dict summary {total_findings, max_score, overall_severity, counts}

    Returns:
        ID dari risk_result yang dibuat, atau None
    """
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Hitung severity counts
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        for f in findings_data:
            sev = f.get("severity", "INFORMATIONAL")
            if sev in counts:
                counts[sev] += 1

        # Insert risk_results
        cursor.execute(
            """
            INSERT INTO risk_results
                (scan_id, target_url, total_findings, max_cvss_score, overall_severity,
                 critical_count, high_count, medium_count, low_count, info_count)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                scan_id,
                target_url,
                summary_data.get("total_findings", len(findings_data)),
                summary_data.get("overall_max_score", 0.0),
                summary_data.get("overall_severity", "INFORMATIONAL"),
                counts["CRITICAL"],
                counts["HIGH"],
                counts["MEDIUM"],
                counts["LOW"],
                counts["INFORMATIONAL"],
            ),
        )
        result_id = cursor.lastrowid

        # Insert each finding
        for f in findings_data:
            cursor.execute(
                """
                INSERT INTO risk_findings
                    (risk_result_id, vulnerability_name, cwe_id, category,
                     cvss_score, cvss_vector, severity, evidence)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    result_id,
                    f.get("vulnerability_name", "Unknown"),
                    f.get("cwe_id", "N/A"),
                    f.get("category", "General Security Weakness"),
                    f.get("cvss_score", 0.0),
                    f.get("cvss_vector", ""),
                    f.get("severity", "INFORMATIONAL"),
                    f.get("evidence", ""),
                ),
            )

        conn.commit()
        logger.info(f"Risk result saved: id={result_id}, findings={len(findings_data)}")
        return result_id

    except Exception as e:
        logger.error(f"Failed to save risk result: {e}")
        if conn:
            conn.rollback()
        return None
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def mark_notified(result_id):
    """Tandai bahwa Telegram notification sudah dikirim."""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE risk_results SET telegram_notified = TRUE WHERE id = %s",
            (result_id,),
        )
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to mark notified: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def get_results(limit=20):
    """Ambil risk results terbaru untuk Dashboard."""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, scan_id, target_url, total_findings,
                   max_cvss_score, overall_severity,
                   critical_count, high_count, medium_count, low_count, info_count,
                   telegram_notified, created_at
            FROM risk_results
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        for r in rows:
            if r.get("created_at") and hasattr(r["created_at"], "isoformat"):
                r["created_at"] = r["created_at"].isoformat()
        return rows
    except Exception as e:
        logger.error(f"Failed to get results: {e}")
        return []
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def get_result_detail(result_id):
    """Ambil detail risk result + findings per ID."""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get result
        cursor.execute("SELECT * FROM risk_results WHERE id = %s", (result_id,))
        result = cursor.fetchone()
        if not result:
            return None

        if result.get("created_at") and hasattr(result["created_at"], "isoformat"):
            result["created_at"] = result["created_at"].isoformat()

        # Get findings
        cursor.execute(
            """
            SELECT id, vulnerability_name, cwe_id, category,
                   cvss_score, cvss_vector, severity, evidence, created_at
            FROM risk_findings
            WHERE risk_result_id = %s
            ORDER BY cvss_score DESC
            """,
            (result_id,),
        )
        findings = cursor.fetchall()
        for f in findings:
            if f.get("created_at") and hasattr(f["created_at"], "isoformat"):
                f["created_at"] = f["created_at"].isoformat()

        result["findings"] = findings
        return result

    except Exception as e:
        logger.error(f"Failed to get result detail: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
