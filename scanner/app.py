"""
app.py
Entry point untuk Scanner Service.
Flask app dengan Nuclei integration dan LLM analysis.
"""

import sys
import os

# Pastikan root directory ada di sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask
from app.api.routes import scanner_bp
from app.config import HOST, PORT, DEBUG, logger


def create_app() -> Flask:
    """Factory function untuk membuat Flask app."""
    app = Flask(__name__)

    # Register blueprint
    app.register_blueprint(scanner_bp)

    # Inisialisasi database (non-blocking, jangan crash jika DB belum ready)
    try:
        from database.connection import init_db
        init_db()
        logger.info("Database initialized")
    except Exception as e:
        logger.warning(f"Database initialization skipped: {e}")
        logger.warning("Scan logging will be unavailable until database is ready")

    logger.info("Scanner Service started")
    logger.info(f"Engine: Nuclei + Gemini 3.5 Flash")

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host=HOST, port=PORT, debug=DEBUG)
