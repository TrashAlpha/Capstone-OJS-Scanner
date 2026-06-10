# Arsitektur Sistem Capstone OJS Scanner

```mermaid
flowchart TB
    %% =========================================
    %% USERS
    %% =========================================
    subgraph USERS["Pengguna"]
        direction LR
        ADMIN["Admin<br/>(Browser)"]
        TGUSER["Telegram User"]
    end

    %% =========================================
    %% ENTRY POINT
    %% =========================================
    subgraph PROXY["Reverse Proxy"]
        NGINX["NGINX<br/>:80<br/>/ -> OJS<br/>/dashboard/ -> Laravel<br/>/scanner/ -> Scanner<br/>/risk/ -> Risk Engine"]
    end

    %% =========================================
    %% DASHBOARD
    %% =========================================
    subgraph DASHBOARD["Dashboard - Laravel PHP (internal :8000, direct :8181)"]
        direction TB
        DASH_SCAN["Scanner Module<br/>(Eksekusi & Monitor Scan)"]
        DASH_REPORT["Report Module<br/>(Lihat Risk Assessment)"]
        DASH_SCHEDULE["Scheduler Module<br/>(Cron Scheduled Scan)"]
        DASH_TG_INT["Telegram Integration<br/>(Kelola Chat ID)"]
    end

    %% =========================================
    %% SCANNER SERVICE
    %% =========================================
    subgraph SCANNER["Scanner Service - Python Flask (:5000)"]
        direction TB
        SCAN_API["REST API<br/>POST /scan<br/>POST /scan/nuclei<br/>POST /scan/internal<br/>POST /scan/full"]

        subgraph SCAN_ENGINES["Scanning Engines"]
            direction LR
            NUCLEI_SVC["NucleiService<br/>(jalankan & parse)"]
            ORCH["ScanOrchestrator<br/>(koordinasi modul)"]
            AUTH_SVC["AuthService<br/>(login OJS)"]
        end

        LLM_SVC["LLMService<br/>(Gemini enrichment)"]
        REPORT_SVC["ReportService<br/>(generate laporan)"]
    end

    %% =========================================
    %% SCANNING TOOLS
    %% =========================================
    subgraph TOOLS["Scanning Tools"]
        direction TB
        subgraph NUCLEI_TOOLS["Nuclei (Go Binary)"]
            NUCLEI_BIN["Nuclei v3<br/>(Go-based binary)"]
            YAML_TMPL["11 YAML Templates<br/>ojs-xss, ojs-sqli, ojs-csrf<br/>ojs-xxe, ojs-lfi, ojs-ssrf<br/>ojs-open-redirect, ojs-email-inject<br/>ojs-plugin-enum, ojs-public-files<br/>ojs-version"]
        end
        subgraph PY_MODULES["Python Modules"]
            EXT_MOD["External Modules (4)<br/>version_scan<br/>security_headers<br/>dir_fuzzing<br/>public_injection"]
            INT_MOD["Internal Modules (5)<br/>security_audit<br/>broken_access<br/>idor<br/>param_injection<br/>file_upload"]
        end
    end

    %% =========================================
    %% RISK ENGINE
    %% =========================================
    subgraph RISK["Risk Engine - Python Flask (:5001)"]
        direction TB
        RISK_API["REST API<br/>POST /analyze<br/>GET /results<br/>GET /results/:id"]
        CVSS_CALC["CVSS Calculator<br/>+ Severity Classifier<br/>(CRITICAL/HIGH/MEDIUM/LOW/INFO)"]
        TG_NOTIFY["Telegram Notifier<br/>(auto-alert jika CRITICAL)"]
    end

    %% =========================================
    %% TELEGRAM BOT
    %% =========================================
    subgraph TELEBOT_SVC["Telegram Bot - Python (Polling)"]
        TELEBOT["Bot Commands<br/>/start -> tampil Chat ID<br/>/chatid -> ulang Chat ID<br/>/help -> bantuan"]
    end

    %% =========================================
    %% TARGET
    %% =========================================
    subgraph TARGET["Target Aplikasi"]
        OJS_APP["Open Journal Systems<br/>(OJS)<br/>internal :80 (via NGINX /)"]
        OJS_DB[("OJS MySQL<br/>:3308<br/>database: ojs")]
    end

    %% =========================================
    %% SHARED DATABASE
    %% =========================================
    subgraph APPDB_SVC["Shared Database - MySQL 8.0 (:3309)"]
        APPDB[("App DB")]
    end

    %% =========================================
    %% EXTERNAL APIs
    %% =========================================
    subgraph EXT_API["External Services"]
        direction LR
        GEMINI["Google Gemini API<br/>gemini-2.5-flash<br/>(Analisis LLM)"]
        TG_API["Telegram Bot API<br/>(Alert & Chat ID)"]
    end

    %% =========================================
    %% CONNECTIONS
    %% =========================================

    %% User -> Proxy
    ADMIN -->|"HTTP Request"| NGINX
    TGUSER <-->|"Chat"| TG_API

    %% Proxy -> Services
    NGINX -->|"/dashboard"| DASHBOARD
    NGINX -->|"/"| OJS_APP

    %% Dashboard -> Backend Services
    DASH_SCAN -->|"POST /scan/*"| SCAN_API
    DASH_REPORT -->|"GET /results"| RISK_API
    DASH_SCHEDULE -->|"Trigger scan"| SCAN_API

    %% Scanner -> Tools
    SCAN_API --> SCAN_ENGINES
    NUCLEI_SVC --> NUCLEI_BIN
    NUCLEI_BIN -->|"baca template"| YAML_TMPL
    ORCH --> EXT_MOD
    ORCH --> INT_MOD
    AUTH_SVC -->|"OJS login"| OJS_APP

    %% Tools -> Target
    NUCLEI_BIN -->|"HTTP probe"| OJS_APP
    EXT_MOD -->|"HTTP unauthenticated"| OJS_APP
    INT_MOD -->|"HTTP authenticated"| OJS_APP

    %% Scanner -> External APIs
    LLM_SVC -->|"Analisis findings"| GEMINI

    %% Scanner -> Database & Risk Engine
    SCAN_API -->|"Simpan scan_runs<br/>+ scan_findings"| APPDB
    SCAN_API -->|"POST /analyze<br/>(forward findings)"| RISK_API

    %% Risk Engine internal
    RISK_API --> CVSS_CALC
    CVSS_CALC -->|"Simpan risk_results<br/>+ risk_findings"| APPDB
    CVSS_CALC -->|"Jika CRITICAL"| TG_NOTIFY
    TG_NOTIFY -->|"Kirim alert"| TG_API

    %% OJS -> DB
    OJS_APP <--> OJS_DB

    %% Telegram Bot
    TG_API <-->|"Polling"| TELEBOT
    TG_API -->|"CRITICAL Alert"| TGUSER

    %% Dashboard reads DB directly
    DASHBOARD -->|"Query langsung<br/>(Eloquent ORM)"| APPDB

    %% =========================================
    %% STYLES
    %% =========================================
    classDef serviceBox fill:#1e3a5f,stroke:#4a9eff,color:#fff
    classDef dbBox fill:#2d4a1e,stroke:#5cb85c,color:#fff
    classDef extBox fill:#4a1e3a,stroke:#ff69b4,color:#fff
    classDef targetBox fill:#4a2e1e,stroke:#ff8c42,color:#fff
    classDef toolBox fill:#2a2a2a,stroke:#888,color:#fff

    class SCAN_API,RISK_API,TELEBOT serviceBox
    class APPDB,OJS_DB dbBox
    class GEMINI,TG_API extBox
    class OJS_APP targetBox
    class NUCLEI_BIN,EXT_MOD,INT_MOD toolBox
```

---

## Ringkasan Komponen

| Komponen | Teknologi | Port | Peran |
|---|---|---|---|
| NGINX | Nginx | :80 | Reverse proxy, satu pintu masuk semua layanan |
| Dashboard | PHP Laravel | internal :8000 (direct :8181) | UI scan, laporan, jadwal, Telegram |
| Scanner Service | Python Flask | :5000 | Orkestrator scan (Nuclei + Python modules) |
| Risk Engine | Python Flask | :5001 | CVSS scoring, klasifikasi severity, alert |
| Telegram Bot | Python (polling) | - | Tampilkan Chat ID ke pengguna |
| OJS App | PHP (target) | internal :80 (via NGINX) | Target yang dipindai |
| Nuclei | Go binary | - | Vulnerability scanner via YAML templates |
| App DB | MySQL 8.0 | :3309 | Shared DB (scan + risk + user data) |
| OJS DB | MySQL 8.0 | :3308 | Database khusus OJS |
| Google Gemini | External API | - | Analisis & enrichment findings dengan LLM |
| Telegram API | External API | - | Kirim alert CRITICAL & Chat ID |

## URL Akses (via NGINX di port 80)

| Layanan | URL |
|---|---|
| OJS | http://localhost/ |
| Dashboard | http://localhost/dashboard/ |
| Scanner API | http://localhost/scanner/ |
| Risk Engine API | http://localhost/risk/ |

## Alur Scan (Ringkas)

```
User -> Dashboard -> Scanner Service
                        - Nuclei (Go) + 11 YAML templates
                        - 4 External Python Modules
                        - 5 Internal Python Modules (auth)
                        - Gemini LLM (enrichment)
                              |
                              v
                        Risk Engine
                              - Hitung CVSS score
                              - Klasifikasi severity
                              - Simpan ke database
                              - Jika CRITICAL -> Telegram Alert
                              |
                              v
                        Dashboard (laporan & visualisasi)
```
