# 🔍 OJS Scanner Service

Scanner kerentanan untuk **Open Journal Systems (OJS)** berbasis **Nuclei** dengan analisis **Gemini 3.5 Flash**.

## 🏗️ Arsitektur

```
Flask API (REST)
    ↓
Nuclei Runner (CLI subprocess)
    ↓
Custom OJS Templates (YAML)
    ↓
JSON Result
    ↓
LLM Analysis (Gemini 3.5 Flash)
    ↓
Final Report → Risk Engine (container terpisah)
```

## 📁 Struktur File

```
📦scanner
 ┣ 📂app
 ┃ ┣ 📂api
 ┃ ┃ ┗ 📜routes.py              ← REST API endpoints
 ┃ ┣ 📂services
 ┃ ┃ ┣ 📜nuclei_service.py      ← Nuclei CLI wrapper
 ┃ ┃ ┣ 📜llm_service.py         ← Gemini 3.5 Flash analysis
 ┃ ┃ ┗ 📜report_service.py      ← Report builder
 ┃ ┣ 📂templates/ojs
 ┃ ┃ ┣ 📜ojs-version.yaml       ← Deteksi versi OJS
 ┃ ┃ ┣ 📜ojs-xxe.yaml           ← CVE-2024-56525
 ┃ ┃ ┣ 📜ojs-xss.yaml           ← CVE-2024-24511/24512/25434, CVE-2023-5894
 ┃ ┃ ┣ 📜ojs-csrf.yaml          ← CVE-2023-5626/6671
 ┃ ┃ ┗ 📜ojs-public-files.yaml  ← Exposed files & dirs
 ┃ ┣ 📂utils
 ┃ ┃ ┗ 📜parser.py               ← Nuclei output parser
 ┃ ┗ 📜config.py                  ← Konfigurasi (env vars)
 ┣ 📂scanners                     ← Scanner internal (Python)
 ┣ 📂database                     ← Scan log history (MySQL)
 ┣ 📜app.py                       ← Entry point
 ┣ 📜requirements.txt
 ┣ 📜Dockerfile
 ┗ 📜README.md
```

## 🌐 API Endpoints

| Method | Endpoint | Deskripsi |
|--------|----------|-----------|
| `GET`  | `/` | Health check |
| `POST` | `/scan` | Full scan (Nuclei + LLM) |
| `POST` | `/scan/nuclei` | Nuclei scan saja |
| `GET`  | `/templates` | List templates |
| `GET`  | `/scans` | Riwayat scan |
| `GET`  | `/scans/<id>` | Detail scan by ID |

### Contoh Request

```bash
# Full scan dengan LLM analysis
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://target-ojs.com"}'

# Nuclei only (tanpa LLM)
curl -X POST http://localhost:5000/scan/nuclei \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://target-ojs.com"}'

# Scan dengan template spesifik
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://target-ojs.com", "templates": ["ojs-version", "ojs-xxe"]}'
```

## 🔧 Environment Variables

| Variable | Default | Deskripsi |
|----------|---------|-----------|
| `OJS_URL` | `http://ojs` | URL target OJS |
| `LLM_API_KEY` | - | API key untuk Gemini |
| `LLM_MODEL` | `gemini-3.5-flash` | Model LLM |
| `NUCLEI_TIMEOUT` | `300` | Timeout scan (detik) |
| `NUCLEI_RATE_LIMIT` | `50` | Rate limit requests |
| `DATABASE_HOST` | `app-db` | MySQL host |
| `DATABASE_NAME` | `appdb` | Database name |

## 🛡️ CVE Coverage

| CVE | Severity | Tipe | Template |
|-----|----------|------|----------|
| CVE-2024-56525 | Critical (9.8) | XXE | `ojs-xxe.yaml` |
| CVE-2023-5626 | High (8.8) | CSRF | `ojs-csrf.yaml` |
| CVE-2023-6671 | Medium (6.3) | CSRF | `ojs-csrf.yaml` |
| CVE-2024-24511 | Medium (6.1) | XSS | `ojs-xss.yaml` |
| CVE-2024-24512 | Medium (6.1) | XSS | `ojs-xss.yaml` |
| CVE-2024-25434 | Medium (6.1) | XSS | `ojs-xss.yaml` |
| CVE-2023-5894 | Medium | XSS | `ojs-xss.yaml` |

## 🐳 Docker

```bash
# Build scanner saja
docker compose build scanner

# Jalankan semua services
docker compose up -d

# Cek logs scanner
docker compose logs -f scanner

# Verify Nuclei di container
docker exec scanner-service nuclei -version
```
