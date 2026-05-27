# Dokumentasi Implementasi Integrasi

## 1. Alur scanner -> risk engine -> dashboard

### Ringkasan arsitektur saat ini
Alur yang sekarang berjalan adalah:

1. User login ke dashboard Laravel.
2. User membuka halaman **Run Scan** lalu mengirim target OJS.
3. Laravel memanggil service **scanner** melalui endpoint `POST /scan`.
4. Scanner menjalankan modul scan yang sudah tersedia dan mengembalikan hasil mentah.
5. Laravel melakukan normalisasi hasil scan agar sesuai format input **risk-engine**.
6. Laravel mengirim hasil yang sudah dinormalisasi ke **risk-engine** melalui endpoint `POST /analyze`.
7. Risk-engine mengklasifikasikan hasil menjadi severity, CVSS, dan kategori CWE.
8. Laravel menyimpan hasil scan ke database MySQL.
9. Dashboard, Scan Logs, Report, dan Detail Scan membaca data dari database.

### Komponen yang ditambahkan/diubah

#### Scanner service
File utama:
- `scanner/app.py`

Perubahan:
- Menambahkan endpoint `POST /scan`
- Endpoint menerima:
  - `target_url`
  - `scan_type`
  - `admin_username` dan `admin_password` (dapat dikirim oleh caller, tetapi pada implementasi saat ini belum diteruskan ke orchestrator dan belum digunakan untuk scan internal/full)
- Endpoint menjalankan `ScanOrchestrator`
- Endpoint mengembalikan hasil mentah scan

#### Laravel service layer
File utama:
- `dashboard/app/Services/ScannerService.php`
- `dashboard/app/Services/RiskEngineService.php`

Fungsi:
- `ScannerService` bertugas memanggil service scanner
- `RiskEngineService` bertugas:
  - normalisasi output scanner
  - mapping severity scanner ke base score jika diperlukan
  - perkiraan `cwe_id` saat data scanner belum lengkap
  - mengirim hasil ke risk-engine

#### Penyimpanan database
Model:
- `dashboard/app/Models/ScanRun.php`
- `dashboard/app/Models/ScanFinding.php`

Migration:
- `dashboard/database/migrations/2026_05_25_000003_create_scan_runs_table.php`
- `dashboard/database/migrations/2026_05_25_000004_create_scan_findings_table.php`

Tabel yang dipakai:
- `scan_runs`
  - menyimpan metadata eksekusi scan
  - target URL
  - type scan
  - summary severity
  - payload scanner
  - payload risk-engine
  - waktu scan
- `scan_findings`
  - menyimpan detail tiap finding
  - kategori
  - finding
  - CVSS
  - severity/risk
  - evidence
  - CWE ID
  - CVSS vector

#### Controller dashboard dan scanner
File utama:
- `dashboard/app/Http/Controllers/DashboardController.php`
- `dashboard/app/Http/Controllers/ScannerController.php`
- `dashboard/app/Http/Controllers/ReportController.php`

Fungsi:
- `DashboardController`
  - membaca summary dari database
  - menampilkan statistik dan recent logs
- `ScannerController`
  - menampilkan logs
  - menjalankan scan
  - menyimpan hasil scan
  - menampilkan detail scan
- `ReportController`
  - menampilkan daftar report/scan run

#### View yang dipakai
- `dashboard/resources/views/dashboard.blade.php`
- `dashboard/resources/views/scanner/run.blade.php`
- `dashboard/resources/views/scanner/logs.blade.php`
- `dashboard/resources/views/scanner/show.blade.php`
- `dashboard/resources/views/reports/index.blade.php`

### Route utama yang sekarang aktif
Di `dashboard/routes/web.php`:
- `GET /dashboard`
- `GET /scanner/run`
- `POST /scanner/run`
- `GET /scanner/logs`
- `GET /scanner/logs/{scanRun}`
- `GET /reports`

### Status implementasi saat ini
Yang sudah jalan:
- Trigger scan dari dashboard
- Scanner mengembalikan raw result
- Risk engine menerima hasil normalisasi
- Hasil risk classification masuk ke dashboard
- Hasil scan tersimpan ke database
- Ada halaman detail scan
- Ada halaman reports

Catatan keterbatasan saat ini:
- Mode `internal` dan `full` belum sepenuhnya diimplementasikan di scanner API, sehingga saat ini real execution masih dominan pada modul external
- Sebagian `cwe_id` dan `base_score` masih dibantu heuristic mapping di Laravel bila scanner belum mengirim field terstruktur

### Cara uji manual
1. Jalankan semua service:
   - `docker compose up -d --build`
2. Jalankan migration:
   - `docker compose exec dashboard php artisan migrate`
3. Seed user default jika diperlukan:
   - `docker compose exec dashboard php artisan db:seed`
4. Login dashboard dengan user default:
   - email: `test@example.com`
   - password: `password`
5. Buka halaman Run Scan
6. Gunakan target internal Docker:
   - `http://ojs`
7. Submit scan external
8. Verifikasi:
   - hasil muncul di dashboard
   - hasil muncul di scan logs
   - detail scan terbuka
   - reports menampilkan histori scan

---

## 2. Telegram notification

### Ringkasan arsitektur saat ini
Implementasi Telegram sekarang dibagi menjadi dua bagian:

1. **Polling bot service** untuk membantu user mengetahui `chat_id`
2. **Laravel TelegramService** untuk mengirim notifikasi hasil scan ke Telegram user

Arsitekturnya:

1. User membuka bot Telegram.
2. User mengirim `/start` atau `/chatid`.
3. Service `telegram-bot` membalas dengan Chat ID user.
4. User membuka halaman **Telegram Alerts** di dashboard.
5. User menyimpan Chat ID tersebut.
6. Saat scan selesai, Laravel mengirim ringkasan hasil scan ke Chat ID yang tersimpan.

### Mengapa pakai polling bot, bukan webhook
Saat ini implementasi sengaja memakai **polling** agar:
- tidak perlu public URL
- tidak perlu konfigurasi webhook Telegram
- lebih mudah untuk development dan demo lokal

Jadi service `telegram-bot` akan terus memanggil Telegram API untuk mengecek pesan baru.

### Service Telegram bot
Folder:
- `telegram-bot/`

File:
- `telegram-bot/app.py`
- `telegram-bot/Dockerfile`
- `telegram-bot/requirements.txt`

Perilaku bot:
- `/start` -> membalas Chat ID user
- `/chatid` -> membalas Chat ID user lagi
- `/help` -> menampilkan bantuan singkat

Service ini dijalankan lewat Docker Compose dengan nama service:
- `telegram-bot`

### Integrasi di dashboard Laravel
File utama:
- `dashboard/app/Services/TelegramService.php`
- `dashboard/app/Http/Controllers/TelegramIntegrationController.php`
- `dashboard/resources/views/integrations/telegram.blade.php`

Fungsi:
- User dapat menyimpan `telegram_chat_id`
- User dapat mengirim **test message** dari dashboard
- Saat scan selesai, Laravel mengirim notifikasi otomatis ke Telegram jika user sudah terkoneksi

### Data user yang ditambahkan
Migration:
- `dashboard/database/migrations/2026_05_25_000005_add_telegram_fields_to_users_table.php`

Field pada tabel `users`:
- `telegram_chat_id`
- `telegram_notifications_enabled`

### Route Telegram di dashboard
- `GET /integrations/telegram`
- `PUT /integrations/telegram`
- `POST /integrations/telegram/test`

### Isi notifikasi scan
Pesan Telegram yang dikirim Laravel berisi ringkasan seperti:
- target URL
- jenis scan
- jumlah finding
- max CVSS
- overall severity
- top findings
- warning jika ada

### Konfigurasi environment
Variable yang dipakai:
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_BOT_USERNAME`

Dipakai di:
- `docker-compose.yml`
- `dashboard/env.example`

### Cara uji manual fitur Telegram
1. Pastikan env sudah diisi:
   - `TELEGRAM_BOT_TOKEN`
   - `TELEGRAM_BOT_USERNAME`
2. Jalankan ulang service:
   - `docker compose up -d --build`
3. Buka Telegram dan cari bot
4. Kirim `/start`
5. Bot akan membalas Chat ID
6. Buka dashboard -> **Telegram Alerts**
7. Paste Chat ID lalu simpan
8. Klik **Send Test Message**
9. Pastikan pesan test masuk
10. Jalankan scan baru dari dashboard
11. Pastikan notifikasi hasil scan juga masuk ke Telegram

### Status implementasi saat ini
Yang sudah jalan:
- halaman Telegram Alerts
- penyimpanan Chat ID per user
- tombol test message
- bot polling untuk `/start` dan `/chatid`
- notifikasi hasil scan otomatis setelah scan berhasil

Catatan:
- user tetap harus pernah chat ke bot terlebih dahulu agar bot bisa mengirim pesan
- tanpa Chat ID yang valid, Laravel tidak bisa mengirim notifikasi
- implementasi saat ini fokus ke private chat user, belum ke grup/channel
