"""
database/models.py
Model dan operasi CRUD untuk scan logs.
"""

import json
from datetime import datetime, timezone
from database.connection import get_connection
from app.config import logger


class ScanLog:
    """Model untuk menyimpan dan mengambil log scan."""

    @staticmethod
    def create(target_url: str, scan_type: str = "full") -> int | None:
        """
        Buat record scan baru dengan status 'running'.

        Returns:
            ID dari record yang dibuat, atau None jika gagal
        """
        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO scan_logs (target_url, scan_type, status)
                VALUES (%s, %s, 'running')
                """,
                (target_url, scan_type),
            )
            conn.commit()

            scan_id = cursor.lastrowid
            logger.info(f"Scan log created: id={scan_id}, target={target_url}")
            return scan_id

        except Exception as e:
            logger.error(f"Failed to create scan log: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    @staticmethod
    def update_completed(scan_id: int, report: dict) -> bool:
        """
        Update record scan setelah selesai.

        Args:
            scan_id: ID scan log
            report: Final report dict
        """
        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor()

            summary = report.get("summary", {})
            findings_count = summary.get("findings_count", {})
            llm = report.get("llm_analysis", {})

            cursor.execute(
                """
                UPDATE scan_logs
                SET status = 'completed',
                    total_findings = %s,
                    critical_count = %s,
                    high_count = %s,
                    medium_count = %s,
                    low_count = %s,
                    info_count = %s,
                    risk_assessment = %s,
                    scan_duration = %s,
                    result_json = %s,
                    completed_at = %s
                WHERE id = %s
                """,
                (
                    summary.get("total_findings", 0),
                    findings_count.get("critical", 0),
                    findings_count.get("high", 0),
                    findings_count.get("medium", 0),
                    findings_count.get("low", 0),
                    findings_count.get("info", 0),
                    llm.get("risk_assessment", "N/A"),
                    report.get("scan_duration_seconds", 0),
                    json.dumps(report, ensure_ascii=False, default=str),
                    datetime.now(timezone.utc),
                    scan_id,
                ),
            )
            conn.commit()

            logger.info(f"Scan log updated: id={scan_id}, status=completed")
            return True

        except Exception as e:
            logger.error(f"Failed to update scan log {scan_id}: {e}")
            return False
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    @staticmethod
    def update_failed(scan_id: int, error_message: str) -> bool:
        """Update record scan yang gagal."""
        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                UPDATE scan_logs
                SET status = 'failed',
                    error_message = %s,
                    completed_at = %s
                WHERE id = %s
                """,
                (error_message, datetime.now(timezone.utc), scan_id),
            )
            conn.commit()

            logger.info(f"Scan log updated: id={scan_id}, status=failed")
            return True

        except Exception as e:
            logger.error(f"Failed to update scan log {scan_id}: {e}")
            return False
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    @staticmethod
    def get_by_id(scan_id: int) -> dict | None:
        """Ambil satu scan log berdasarkan ID."""
        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute("SELECT * FROM scan_logs WHERE id = %s", (scan_id,))
            row = cursor.fetchone()

            if row and row.get("result_json"):
                try:
                    row["result_json"] = json.loads(row["result_json"])
                except json.JSONDecodeError:
                    pass

            return row

        except Exception as e:
            logger.error(f"Failed to get scan log {scan_id}: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    @staticmethod
    def get_recent(limit: int = 20) -> list[dict]:
        """Ambil scan logs terbaru."""
        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT id, target_url, scan_type, status,
                       total_findings, critical_count, high_count,
                       medium_count, low_count, info_count,
                       risk_assessment, scan_duration,
                       error_message, created_at, completed_at
                FROM scan_logs
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (limit,),
            )

            return cursor.fetchall()

        except Exception as e:
            logger.error(f"Failed to get recent scan logs: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
