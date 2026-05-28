"""
database/connection.py
Koneksi ke MySQL database untuk menyimpan log scan.
Menggunakan mysql-connector-python.
"""

# pyrefly: ignore [missing-import]
import mysql.connector
from mysql.connector import pooling
from app.config import (
    DATABASE_HOST,
    DATABASE_PORT,
    DATABASE_NAME,
    DATABASE_USER,
    DATABASE_PASSWORD,
    logger,
)

# Connection pool untuk efisiensi
_pool = None


def get_pool():
    """Lazy initialization connection pool."""
    global _pool
    if _pool is None:
        try:
            _pool = pooling.MySQLConnectionPool(
                pool_name="scanner_pool",
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
            logger.info(f"Database pool initialized: {DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_NAME}")
        except Exception as e:
            logger.error(f"Failed to create database pool: {e}")
            raise
    return _pool


def get_connection():
    """Ambil koneksi dari pool."""
    try:
        return get_pool().get_connection()
    except Exception as e:
        logger.error(f"Failed to get database connection: {e}")
        raise


def init_db():
    """
    Inisialisasi tabel database jika belum ada.
    Dipanggil saat aplikasi startup.
    """
    import time
    conn = None
    cursor = None
    max_retries = 5
    
    for attempt in range(max_retries):
        try:
            conn = get_connection()
            cursor = conn.cursor()

            # Tabel untuk log scan history
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    target_url VARCHAR(500) NOT NULL,
                    scan_type VARCHAR(50) NOT NULL DEFAULT 'full',
                    status VARCHAR(20) NOT NULL DEFAULT 'running',
                    total_findings INT DEFAULT 0,
                    critical_count INT DEFAULT 0,
                    high_count INT DEFAULT 0,
                    medium_count INT DEFAULT 0,
                    low_count INT DEFAULT 0,
                    info_count INT DEFAULT 0,
                    risk_assessment VARCHAR(50) DEFAULT NULL,
                    scan_duration FLOAT DEFAULT NULL,
                    result_json LONGTEXT DEFAULT NULL,
                    error_message TEXT DEFAULT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP NULL DEFAULT NULL,
                    INDEX idx_target_url (target_url(255)),
                    INDEX idx_status (status),
                    INDEX idx_created_at (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)

            conn.commit()
            logger.info("Database tables initialized successfully")
            break

        except Exception as e:
            logger.warning(f"Database initialization failed on attempt {attempt+1}/{max_retries}: {e}")
            if attempt < max_retries - 1:
                time.sleep(3)
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
