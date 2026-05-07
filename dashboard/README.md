# Dashboard — OJS Security Scanner

Dashboard berbasis Laravel untuk menampilkan hasil audit keamanan OJS.

## Persyaratan
- PHP 8.4+
- Composer
- Node.js & npm
- MySQL

## Setup setelah clone

### 1. Install PHP dependencies
```bash
composer install --ignore-platform-reqs
```

### 2. Install Node dependencies
```bash
npm install
```

### 3. Build assets
```bash
npm run build
```

### 4. Setup environment
```bash
cp .env.example .env
php artisan key:generate
```

### 5. Sesuaikan `.env`
```env
DB_HOST=ojs-db
DB_DATABASE=ojs
DB_USERNAME=ojsuser
DB_PASSWORD=ojs123
SESSION_DRIVER=file
CACHE_STORE=file
```

### 6. Jalankan migrasi
```bash
php artisan migrate
```

### 7. Jalankan server (development)
```bash
php artisan serve
```

## Catatan
- Folder `vendor/` dan `node_modules/` tidak di-push ke GitHub — generate ulang dengan langkah di atas
- Untuk production, jalankan via Docker sesuai `docker-compose.yml` di root project