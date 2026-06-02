#!/bin/sh
set -e

cd /app

if [ ! -f .env ]; then
  cp env.example .env
fi

upsert_env() {
  key="$1"
  value="$2"

  if [ -z "$value" ]; then
    return
  fi

  escaped_value=$(printf '%s' "$value" | sed 's/[\\&/]/\\&/g')

  if grep -q "^${key}=" .env; then
    sed -i "s/^${key}=.*/${key}=${escaped_value}/" .env
  else
    printf '\n%s=%s\n' "$key" "$value" >> .env
  fi
}

upsert_env "TELEGRAM_BOT_USERNAME" "$TELEGRAM_BOT_USERNAME"
upsert_env "TELEGRAM_BOT_TOKEN" "$TELEGRAM_BOT_TOKEN"
upsert_env "SCANNER_URL" "$SCANNER_URL"
upsert_env "RISK_ENGINE_URL" "$RISK_ENGINE_URL"
upsert_env "APP_KEY" "$APP_KEY"

if ! grep -Eq '^APP_KEY=.+$' .env; then
  php artisan key:generate --force
fi

mkdir -p /app/storage/logs /app/storage/framework/sessions /app/storage/framework/views /app/storage/framework/cache
chmod -R 775 /app/storage
php artisan optimize:clear || true
php artisan config:clear || true
php artisan cache:clear || true
php artisan view:clear || true
php artisan migrate --force
php artisan db:seed --force || true

# Jalankan Laravel scheduler (memanggil schedule:run tiap menit) sebagai proses latar.
# Dipakai untuk automasi scan terjadwal (scans:dispatch-due & scans:finalize).
php artisan schedule:work >> /app/storage/logs/scheduler.log 2>&1 &

exec php artisan serve --host=0.0.0.0 --port=8000
