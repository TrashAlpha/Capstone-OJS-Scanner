"""
app.py
Entry point untuk Scanner Service.
Flask app dengan Nuclei integration dan LLM analysis.
"""

import sys
import os
import threading
import time

# Pastikan root directory ada di sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask
from app.api.routes import scanner_bp
from app.config import HOST, PORT, DEBUG, logger


def _init_db_background():
    """
    Retry init_db di background thread sampai berhasil.
    Menangani race condition antara scanner dan MySQL saat Docker startup.
    """
    max_attempts = 24  # 24 × 5s = 2 menit
    for attempt in range(max_attempts):
        try:
            from database.connection import init_db
            init_db()
            logger.info("Database initialized successfully")
            return
        except Exception as e:
            if attempt == 0:
                logger.warning(f"Database not ready yet, retrying in background... ({e})")
            time.sleep(5)
    logger.error("Database initialization failed after 2 minutes — scan logging unavailable")


def create_app() -> Flask:
    """Factory function untuk membuat Flask app."""
    app = Flask(__name__)

    # Register blueprint
    app.register_blueprint(scanner_bp)

    # Inisialisasi database di background thread agar tidak block startup
    thread = threading.Thread(target=_init_db_background, daemon=True)
    thread.start()

    logger.info("Scanner Service started")
    logger.info("Engine: Nuclei + Gemini 3.5 Flash")

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host=HOST, port=PORT, debug=DEBUG)
