#!/bin/sh
set -e

cd /app

if [ ! -f .env ]; then
  cp env.example .env
fi

php artisan key:generate --force
php artisan config:clear || true
php artisan cache:clear || true
php artisan migrate --force
php artisan db:seed --force || true

exec php artisan serve --host=0.0.0.0 --port=8000
