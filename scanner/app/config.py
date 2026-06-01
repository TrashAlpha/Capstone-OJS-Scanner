"""
app/config.py
Konfigurasi terpusat untuk scanner service.
Semua setting diambil dari environment variables dengan default value.
"""

import os
import logging

# ── Flask ──────────────────────────────────────────────────────
DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"
HOST = os.getenv("FLASK_HOST", "0.0.0.0")
PORT = int(os.getenv("FLASK_PORT", "5000"))

# ── Nuclei ─────────────────────────────────────────────────────
NUCLEI_BIN = os.getenv("NUCLEI_BIN", "/usr/local/bin/nuclei")
TEMPLATES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "templates", "ojs"
)
NUCLEI_TIMEOUT = int(os.getenv("NUCLEI_TIMEOUT", "300"))
NUCLEI_RATE_LIMIT = int(os.getenv("NUCLEI_RATE_LIMIT", "50"))

# ── LLM (Gemini 3.5 Flash) ────────────────────────────────────
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini")
LLM_MODEL = os.getenv("LLM_MODEL", "gemini-2.5-flash")

# ── Target default ─────────────────────────────────────────────
OJS_URL = os.getenv("OJS_URL", "http://ojs")

# ── Database (MySQL untuk scan log) ────────────────────────────
DATABASE_HOST = os.getenv("DATABASE_HOST", "app-db")
DATABASE_PORT = int(os.getenv("DATABASE_PORT", "3306"))
DATABASE_NAME = os.getenv("DATABASE_NAME", "appdb")
DATABASE_USER = os.getenv("DATABASE_USER", "appuser")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD", "app123")

# ── Internal Scanner ───────────────────────────────────────────
OJS_ADMIN_USERNAME = os.getenv("OJS_ADMIN_USERNAME", "")
OJS_ADMIN_PASSWORD = os.getenv("OJS_ADMIN_PASSWORD", "")
INTERNAL_SCAN_TIMEOUT = int(os.getenv("INTERNAL_SCAN_TIMEOUT", "600"))

# ── Logging ────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger("scanner")
