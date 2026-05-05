# 📦 OJS Dockerized System with Scanner & Risk Engine

Project ini merupakan implementasi **Open Journal Systems (OJS)** berbasis Docker dengan beberapa services:

* 🔁 Reverse Proxy (Nginx) -> tidak digunakan saat deployment gcp
* 📰 OJS (Core System)
* 🧠 Risk Engine (Python)
* 🔍 Scanner Service (Python)
* 🗄️ MySQL

---

# 🤝 How To Contribute

Ikuti langkah berikut untuk berkontribusi dengan baik:

## 1. Buat Branch Baru

**WAJIB** membuat branch baru untuk setiap perubahan (jangan langsung ke `main`):

```bash
git checkout -b feature/nama-fitur
```

Contoh:

```bash
git checkout -b feature/add-scanner-endpoint
git checkout -b fix/nginx-routing
```

## 2. Lakukan Perubahan

* Tambahkan fitur / perbaikan
* Pastikan project tetap bisa dijalankan
* Ikuti standar commit (semantic commit) -> lihat di `How-To-Commit.md`
  

## 3. Commit & Push

```bash
git add .
git commit -m "feat: add scanner endpoint"
git push origin feature/nama-fitur
```


## 4. Buat Pull Request

* Buka repository utama
* Klik **Compare & Pull Request**
* Jelaskan perubahan yang dilakukan



## 5. Review

Perubahan akan direview bersama sebelum merge ke branch `main`.

---

# 🖥️ Persyaratan

## 🔹 Windows

Install:

* Docker Desktop

Pastikan:

* WSL2 aktif
* Docker Desktop dalam keadaan **Running**

---

## 🔹 Linux / Ubuntu (Lebih Disarankan)

Install:

* Docker
* Docker Compose

---

# 📥 Clone Repository

### Windows (PowerShell / CMD)

```bash
git clone https://github.com/TrashAlpha/Capstone-OJS-Scanner.git
cd Capstone-OJS-Scanner
```

### Linux

```bash
git clone https://github.com/TrashAlpha/Capstone-OJS-Scanner.git
cd Capstone-OJS-Scanner
```

---

# ⚠️ Sebelum Menjalankan

## 🔹 Windows

Pastikan:

* Docker Desktop sudah aktif
* Tidak ada aplikasi lain yang memakai port 80 (misalnya IIS, XAMPP, dll)

Cek port:

```powershell
netstat -ano | findstr :80
```

---

## 🔹 Linux

```bash
sudo lsof -i :80
```

Jika ada Apache:

```bash
sudo systemctl stop apache2
```

---

# ▶️ Menjalankan Project

## 🔹 Windows (PowerShell)

```powershell
docker compose up -d --build
```

## 🔹 Linux

```bash
docker compose up -d --build
```

---

# 🔍 Cek Container

```bash
docker ps
```

Pastikan semua berjalan:

* nginx-proxy
* ojs-app
* ojs-mysql
* scanner-service
* risk-engine-service
* app-mysql
* laravel-dashboard

---

# 🌐 Akses Aplikasi

Buka browser:

```id="url1"
http://localhost
```

---

# 🧩 Routing

| URL          | Service     |
| ------------ | ----------- |
| `/`          | OJS         |
| `/dashboard` | Laravel     |
| `/risk`      | Risk Engine |
| `/scanner`   | Scanner     |

---

# 🛠️ Instalasi OJS

Saat pertama kali dijalankan:

1. Buka `http://localhost`
2. Isi konfigurasi:

```text
Database: MySQL
Host: ojs-db
User: ojsuser
Password: ojs123
Database Name: ojs
```

---

# 🔄 Reset Jika Error

Jika muncul error:

```text
Table already exists
```

## Windows / Linux:

```bash
docker compose down -v
docker compose up -d
```

---

# 📁 Struktur Project

```text
ojs-docker/
├── docker-compose.yml
├── nginx/
├── dashboard/
├── scanner/
├── risk-engine/
└── ojs-files/ (ignored)
```

---

# 🐛 Debugging

## Cek log

```bash
docker compose logs -f
```

## Restart service

```bash
docker compose restart
```

---

# ⚠️ Catatan Penting

* Jangan upload folder `ojs-files/`
* Gunakan `.env.example` untuk konfigurasi
* Semua service berjalan dalam network Docker
