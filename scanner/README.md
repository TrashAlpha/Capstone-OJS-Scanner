# 🔍 OJS Scanner Service

Scanner kerentanan untuk **Open Journal Systems (OJS)** berbasis **Nuclei** dan **Python scanner modules** dengan analisis **Gemini 3.5 Flash**.

---

## 🏗️ Arsitektur

Scanner memiliki **dua pipeline scan** yang saling melengkapi:

```
┌─────────────────────────────────────────────────────────────┐
│                    EXTERNAL SCAN (tanpa login)              │
│                                                             │
│  POST /scan  atau  POST /scan/nuclei                        │
│      │                                                      │
│      ├── Nuclei Runner ──► 11 Custom OJS Templates          │
│      └── Python Modules ──► VersionScanner                  │
│                             SecurityHeadersScanner          │
│                             DirFuzzingScanner               │
│                             PublicInjectionScanner          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│               INTERNAL SCAN (dengan login admin)            │
│                                                             │
│  POST /scan/internal  { target_url, username, password }    │
│      │                                                      │
│      ├── OJSAuthService.login() ──► requests.Session        │
│      └── Python Modules ──► SecurityAuditScanner            │
│                             BrokenAccessScanner             │
│                             IDORScanner                     │
│                             ParamInjectionScanner           │
│                             FileUploadScanner               │
└─────────────────────────────────────────────────────────────┘

Semua findings → LLM Analysis (Gemini) → Risk Engine → Dashboard
```

---

## 📁 Struktur File

```
📦 scanner/
 ┣ 📂 app/
 ┃ ┣ 📂 api/
 ┃ ┃ ┗ 📜 routes.py                ← REST API endpoints
 ┃ ┣ 📂 services/
 ┃ ┃ ┣ 📜 auth_service.py          ← OJS login & session management (NEW)
 ┃ ┃ ┣ 📜 nuclei_service.py        ← Nuclei CLI wrapper
 ┃ ┃ ┣ 📜 llm_service.py           ← Gemini 3.5 Flash analysis
 ┃ ┃ ┗ 📜 report_service.py        ← Report builder
 ┃ ┣ 📂 templates/ojs/             ← 11 Nuclei YAML templates
 ┃ ┃ ┣ 📜 ojs-version.yaml         ← Deteksi versi OJS
 ┃ ┃ ┣ 📜 ojs-xxe.yaml             ← CVE-2024-56525 (XXE)
 ┃ ┃ ┣ 📜 ojs-xss.yaml             ← CVE-2024-24511/12, CVE-2023-5894, dll
 ┃ ┃ ┣ 📜 ojs-csrf.yaml            ← CVE-2023-5626/6671
 ┃ ┃ ┣ 📜 ojs-public-files.yaml    ← Exposed files & dirs
 ┃ ┃ ┣ 📜 ojs-sqli.yaml            ← SQL Injection (NEW)
 ┃ ┃ ┣ 📜 ojs-lfi.yaml             ← Path Traversal / LFI (NEW)
 ┃ ┃ ┣ 📜 ojs-open-redirect.yaml   ← Open Redirect (NEW)
 ┃ ┃ ┣ 📜 ojs-ssrf.yaml            ← SSRF (NEW)
 ┃ ┃ ┣ 📜 ojs-plugin-enum.yaml     ← Plugin Enumeration (NEW)
 ┃ ┃ ┗ 📜 ojs-email-inject.yaml    ← Email Header Injection (NEW)
 ┃ ┣ 📂 utils/
 ┃ ┃ ┗ 📜 parser.py                ← Nuclei output parser + Python findings converter
 ┃ ┗ 📜 config.py                  ← Konfigurasi (env vars)
 ┣ 📂 scanners/                    ← Python scanner modules
 ┃ ┣ 📜 base.py                    ← ScannerModule ABC + Finding dataclass
 ┃ ┣ 📜 orchestrator.py            ← Koordinator semua modul
 ┃ ┣ 📂 external/                  ← Unauthenticated checks
 ┃ ┃ ┣ 📜 version_scan.py          ← Deteksi versi + CVE mapping
 ┃ ┃ ┣ 📜 security_headers.py      ← Audit HTTP security headers
 ┃ ┃ ┣ 📜 dir_fuzzing.py           ← Fuzzing path sensitif OJS (NEW)
 ┃ ┃ ┗ 📜 public_injection.py      ← Test injection form publik (NEW)
 ┃ ┗ 📂 internal/                  ← Authenticated checks
 ┃   ┣ 📜 security_audit.py        ← Audit konfigurasi admin (NEW)
 ┃   ┣ 📜 broken_access.py         ← Test privilege escalation (NEW)
 ┃   ┣ 📜 idor.py                  ← Test IDOR (NEW)
 ┃   ┣ 📜 param_injection.py       ← Test SQLi, XSS, SSTI (NEW)
 ┃   ┗ 📜 file_upload.py           ← Test file upload bypass (NEW)
 ┣ 📂 database/                    ← Scan log history (MySQL)
 ┣ 📜 app.py                       ← Entry point
 ┣ 📜 requirements.txt
 ┗ 📜 Dockerfile
```

---

## 🌐 API Endpoints

| Method | Endpoint | Deskripsi | Auth |
|--------|----------|-----------|------|
| `GET`  | `/` | Health check | Tidak |
| `POST` | `/scan` | Full scan: Nuclei + Python external + LLM | Tidak |
| `POST` | `/scan/nuclei` | Nuclei scan saja (tanpa LLM) | Tidak |
| `POST` | `/scan/internal` | Internal scan dengan kredensial admin | **Ya** |
| `POST` | `/scan/auth-test` | Verifikasi kredensial OJS | **Ya** |
| `GET`  | `/templates` | List semua Nuclei templates | Tidak |
| `GET`  | `/scans` | Riwayat scan | Tidak |
| `GET`  | `/scans/<id>` | Detail scan berdasarkan ID | Tidak |

---

## 🚀 Cara Menjalankan Scan

### 1. External Scan (Tanpa Login)

External scan menjalankan Nuclei dengan 11 template OJS + Python scanner modules
tanpa memerlukan kredensial ke website target.

```bash
# Full scan (Nuclei + Python modules + LLM analysis)
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://target-ojs.com",
    "scan_profile": "general"
  }'

# Nuclei only (cepat, tanpa LLM)
curl -X POST http://localhost:5000/scan/nuclei \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://target-ojs.com",
    "scan_profile": "ojs_only"
  }'
```

**Parameter `scan_profile`:**
- `general` (default) — template OJS + automatic scan teknologi yang terdeteksi
- `ojs_only` — hanya template OJS custom (lebih cepat)

### 2. Internal Scan (Dengan Kredensial Admin)

Internal scan login ke OJS menggunakan kredensial yang diberikan, lalu menjalankan
pemeriksaan yang hanya bisa dilakukan dari dalam sistem (privilege escalation, IDOR,
file upload bypass, audit konfigurasi, dll).

**Langkah 1 — Verifikasi kredensial dulu (opsional tapi disarankan):**

```bash
curl -X POST http://localhost:5000/scan/auth-test \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://target-ojs.com",
    "username": "admin",
    "password": "secret"
  }'
```

Response:
```json
{
  "valid": true,
  "role": "admin",
  "message": "Login berhasil sebagai 'admin'"
}
```

**Langkah 2 — Jalankan internal scan:**

```bash
curl -X POST http://localhost:5000/scan/internal \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://target-ojs.com",
    "username": "admin",
    "password": "secret"
  }'
```

Response (202 Accepted — scan berjalan di background):
```json
{
  "message": "Internal scan started in background",
  "scan_id": 42,
  "target_url": "http://target-ojs.com",
  "authenticated_role": "admin",
  "status": "running"
}
```

**Langkah 3 — Cek hasil scan:**

```bash
curl http://localhost:5000/scans/42
```

### 3. Cek Status dan Hasil Scan

```bash
# Riwayat scan terbaru (default 20, max 100)
curl http://localhost:5000/scans
curl http://localhost:5000/scans?limit=50

# Detail scan tertentu
curl http://localhost:5000/scans/42

# List template yang tersedia
curl http://localhost:5000/templates
```

---

## 🛡️ CVE & Vulnerability Coverage

### Nuclei Templates (External — Tanpa Login)

| CVE / Vulnerability | Severity | Tipe | Template |
|---|---|---|---|
| CVE-2024-56525 | Critical (9.8) | XXE via XML Import | `ojs-xxe.yaml` |
| CVE-2023-5626 | High (8.8) | CSRF | `ojs-csrf.yaml` |
| CVE-2019-17648 | Critical | SQL Injection | `ojs-sqli.yaml` |
| Generic SQLi | High | SQL Injection | `ojs-sqli.yaml` |
| CVE-2023-6671 | Medium (6.3) | CSRF | `ojs-csrf.yaml` |
| CVE-2024-24511 | Medium (6.1) | Stored XSS (Title) | `ojs-xss.yaml` |
| CVE-2024-24512 | Medium (6.1) | Stored XSS (Subtitle) | `ojs-xss.yaml` |
| CVE-2024-25434 | Medium (6.1) | Stored XSS (Publicname) | `ojs-xss.yaml` |
| CVE-2023-5894 | Medium | Stored XSS | `ojs-xss.yaml` |
| CVE-2022-24181 | Medium | Reflected XSS (X-Forwarded-Host) | `ojs-xss.yaml` |
| Path Traversal / LFI | High | File Inclusion | `ojs-lfi.yaml` |
| Open Redirect | Medium | URL Redirection | `ojs-open-redirect.yaml` |
| SSRF | High | Server-Side Request Forgery | `ojs-ssrf.yaml` |
| Plugin Enumeration | Info/Medium | Information Disclosure | `ojs-plugin-enum.yaml` |
| Email Header Injection | Medium | CRLF Injection | `ojs-email-inject.yaml` |
| Sensitive File Exposure | Various | Misconfiguration | `ojs-public-files.yaml` |

### Python Internal Modules (Butuh Login Admin)

| Modul | Vulnerability yang Dicek |
|---|---|
| `SecurityAuditScanner` | Default credentials, installer aktif, upload file types berbahaya, password policy lemah, debug mode |
| `BrokenAccessScanner` | Akses endpoint admin tanpa role admin, horizontal privilege escalation, API access control |
| `IDORScanner` | Akses submission milik user lain, data privat user, file artikel belum publish |
| `ParamInjectionScanner` | SQL injection admin, Stored XSS journal title, SSTI email template, CRLF injection |
| `FileUploadScanner` | PHP extension bypass, double extension bypass, SVG XSS upload, null byte bypass |

---

## 🔧 Environment Variables

| Variable | Default | Deskripsi |
|---|---|---|
| `LLM_API_KEY` | — | API key Google Gemini |
| `LLM_MODEL` | `gemini-3.5-flash` | Model LLM |
| `NUCLEI_BIN` | `/usr/local/bin/nuclei` | Path ke binary Nuclei |
| `NUCLEI_TIMEOUT` | `300` | Timeout scan Nuclei (detik) |
| `NUCLEI_RATE_LIMIT` | `50` | Rate limit requests/detik |
| `RISK_ENGINE_URL` | `http://risk-engine:5000` | URL Risk Engine service |
| `OJS_ADMIN_USERNAME` | — | Username admin OJS (opsional, fallback default) |
| `OJS_ADMIN_PASSWORD` | — | Password admin OJS (opsional, fallback default) |
| `INTERNAL_SCAN_TIMEOUT` | `600` | Timeout internal scan (detik) |
| `DATABASE_HOST` | `app-db` | MySQL host |
| `DATABASE_NAME` | `appdb` | Database name |
| `DATABASE_USER` | `appuser` | Database user |
| `DATABASE_PASSWORD` | `app123` | Database password |
| `LOG_LEVEL` | `INFO` | Level logging (DEBUG/INFO/WARNING) |

---

## 🐳 Docker

```bash
# Build scanner
docker compose build scanner

# Jalankan semua services
docker compose up -d

# Cek log scanner secara live
docker compose logs -f scanner

# Masuk ke container scanner
docker exec -it scanner-service bash

# Verifikasi Nuclei terinstall
docker exec scanner-service nuclei -version

# Cek template yang tersedia (dari dalam container)
curl http://localhost:5000/templates
```

---

## 🔄 Flow Kerja Scanner

```
Target URL diterima
    │
    ├── External Pipeline
    │   ├── Nuclei scan (11 templates OJS)
    │   ├── VersionScanner + SecurityHeadersScanner
    │   ├── DirFuzzingScanner + PublicInjectionScanner
    │   └── Findings → LLM Analysis → Risk Engine → DB
    │
    └── Internal Pipeline (jika /scan/internal)
        ├── OJSAuthService.login(username, password)
        ├── SecurityAuditScanner + BrokenAccessScanner
        ├── IDORScanner + ParamInjectionScanner + FileUploadScanner
        └── Findings → Risk Engine → DB
```

Semua findings dari kedua pipeline dikirim ke **Risk Engine** untuk CVSS scoring,
klasifikasi CWE, dan Telegram notification jika ditemukan kerentanan kritis.
