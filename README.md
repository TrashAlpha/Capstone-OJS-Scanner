# 📦 OJS Security Scanner — Dockerized Vulnerability Scanning Platform

Platform pemindaian kerentanan otomatis untuk **Open Journal Systems (OJS)**, berbasis Docker Compose. Sistem memadukan pemindaian eksternal & internal, analisis berbantuan **LLM (Google Gemini)**, penilaian risiko berbasis **CVSS**, dan notifikasi **Telegram** real-time.

🌐 **Situs diseminasi:** [trashalpha.github.io/Capstone-OJS-Scanner](https://trashalpha.github.io/Capstone-OJS-Scanner/)
📐 **Diagram arsitektur lengkap:** [ARCHITECTURE.md](ARCHITECTURE.md)

---

# 🧩 Komponen Sistem

| Service | Teknologi | Peran |
| ------- | --------- | ----- |
| 🔁 **Nginx** | Reverse proxy | Satu pintu masuk semua layanan di port `80` |
| 📰 **OJS** | PHP (target) | Aplikasi Open Journal Systems yang dipindai |
| 🔍 **Scanner Service** | Python Flask + Nuclei (Go) | Orkestrator pemindaian (eksternal + internal) |
| ⚖️ **Risk Engine** | Python Flask | CVSS scoring, klasifikasi severity, alert |
| 📊 **Dashboard** | Laravel (PHP 8.4) | UI scan, laporan, jadwal, integrasi Telegram |
| 🤖 **Telegram Bot** | Python (polling) | Menampilkan Chat ID ke pengguna |
| 🗄️ **MySQL ×2** | MySQL 8.0 | DB OJS + DB aplikasi (scan, risk, user) |

---

# ✨ Fitur Utama

* **Pemindaian Eksternal** — Nuclei dengan 11 template khusus OJS + 4 modul Python tanpa autentikasi (versi, security headers, dir fuzzing, public injection).
* **Pemindaian Internal** — 5 modul terautentikasi (security audit, broken access, IDOR, param injection, file upload).
* **Tiga mode scan** — `external`, `internal`, dan `full` (gabungan).
* **Analisis LLM** — Google Gemini (`gemini-2.5-flash`) memperkaya temuan dengan konteks & rekomendasi.
* **Penilaian Risiko CVSS** — skor CVSS, klasifikasi severity (Critical → Info), dan agregasi temuan.
* **Notifikasi Telegram** — alert otomatis saat ditemukan kerentanan severity Critical.
* **Dashboard & Penjadwalan** — eksekusi scan, laporan, jadwal cron, dan integrasi Telegram dalam satu tempat.

---

# 🛠️ Tech Stack

* **Backend pemindai:** Python 3 · Flask · Nuclei v3 (Go binary) · template YAML kustom
* **LLM:** Google Gemini (`gemini-2.5-flash`)
* **Dashboard:** Laravel (PHP 8.4) · Blade · Vite · Eloquent ORM
* **Database:** MySQL 8.0 (dua instance)
* **Infrastruktur:** Docker Compose · Nginx · Telegram Bot API

---

# 🖥️ Persyaratan

## 🔹 Windows

* Docker Desktop (WSL2 aktif, status **Running**)

## 🔹 Linux / Ubuntu (Lebih Disarankan)

* Docker
* Docker Compose

---

# 📥 Clone Repository

```bash
git clone https://github.com/TrashAlpha/Capstone-OJS-Scanner.git
cd Capstone-OJS-Scanner
```

---

# 🔑 Konfigurasi Environment (`.env`)

Buat file `.env` di root project. Variabel berikut digunakan oleh Scanner, Risk Engine, dan Telegram Bot:

```env
# LLM — wajib untuk analisis Gemini
LLM_API_KEY=your_gemini_api_key

# Telegram — opsional, untuk notifikasi alert & fitur Chat ID
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
TELEGRAM_BOT_USERNAME=your_bot_username
```

> Tanpa `LLM_API_KEY`, pemindaian tetap berjalan tetapi tahap pengayaan LLM dilewati.
> Konfigurasi Dashboard (Laravel) di-inject otomatis lewat `docker-compose.yml`.

---

# ⚠️ Sebelum Menjalankan

Pastikan **port 80 tidak dipakai** aplikasi lain (IIS, XAMPP, Apache, dll).

## 🔹 Windows

```powershell
netstat -ano | findstr :80
```

## 🔹 Linux

```bash
sudo lsof -i :80
# Jika ada Apache:
sudo systemctl stop apache2
```

---

# ▶️ Menjalankan Project

```bash
docker compose up -d --build
```

---

# 🔍 Cek Container

```bash
docker compose ps
```

Pastikan semua berjalan:

* `nginx-proxy`
* `ojs-app`
* `ojs-mysql`
* `scanner-service`
* `risk-engine-service`
* `mysql-app`
* `laravel-dashboard`
* `telegram-bot-service`

---

# 🌐 Akses Aplikasi

Semua layanan diakses melalui **satu pintu Nginx di port 80**:

| URL | Service |
| --- | ------- |
| `http://localhost/` | OJS |
| `http://localhost/dashboard/` | Dashboard (Laravel) |
| `http://localhost/scanner/` | Scanner API |
| `http://localhost/risk/` | Risk Engine API |

### Port langsung (untuk debug/development)

| URL | Service |
| --- | ------- |
| `http://localhost:8181` | Dashboard (langsung, tanpa Nginx) |
| `http://localhost:5000` | Scanner API (langsung) |
| `http://localhost:5001` | Risk Engine API (langsung) |
| `localhost:3308` | MySQL OJS |
| `localhost:3309` | MySQL aplikasi (`appdb`) |

> Dashboard dilayani Nginx di sub-path `/dashboard/`. Mengetik `http://localhost/dashboard` (tanpa trailing slash) akan otomatis di-redirect ke `/dashboard/`.

---

# 🛠️ Instalasi OJS

Saat pertama kali dijalankan, buka `http://localhost/` lalu isi konfigurasi database:

```text
Database Driver : MySQL
Host            : ojs-db
Username        : ojsuser
Password        : ojs123
Database Name   : ojs
```

---

# 🔄 Reset Jika Error

Jika muncul error seperti `Table already exists`:

```bash
docker compose down -v
docker compose up -d --build
```

> ⚠️ `-v` menghapus volume database (data OJS & appdb akan hilang).

---

# 📁 Struktur Project

```text
Capstone-OJS-Scanner/
├── docker-compose.yml
├── .env                  # variabel rahasia (ignored)
├── ARCHITECTURE.md       # diagram & detail arsitektur
├── nginx/                # konfigurasi reverse proxy
├── ojs/                  # OJS (target)
├── scanner/              # Scanner Service
├── risk-engine/          # Risk Engine
├── telegram-bot/         # Telegram Bot
├── dashboard/            # Dashboard (Laravel)
├── docs/                 # Situs diseminasi (GitHub Pages)
└── ojs-files/            # data OJS (ignored)
```

---

# 🐛 Debugging

```bash
# Lihat semua log
docker compose logs -f

# Log service tertentu
docker compose logs -f scanner
docker compose logs -f dashboard

# Restart service
docker compose restart nginx dashboard
```

---

# 🤝 How To Contribute

**WAJIB** membuat branch baru untuk setiap perubahan (jangan langsung ke `main`).

```bash
# 1. Branch baru
git checkout -b feature/nama-fitur

# 2. Commit (semantic commit -> lihat How-To-Commit.md)
git add .
git commit -m "feat: add scanner endpoint"

# 3. Push
git push origin feature/nama-fitur
```

Lalu buka **Compare & Pull Request** di repository, jelaskan perubahan, dan tunggu review sebelum merge ke `main`.

---

# ⚠️ Catatan Penting

* Jangan upload folder `ojs-files/` dan file `.env`.
* Semua service berjalan dalam satu Docker network (`appnet`).
* Komunikasi antar-container memakai nama service (mis. `http://scanner:5000`), tanpa lewat Nginx.
