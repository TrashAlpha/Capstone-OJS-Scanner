# =========================
# BASE IMAGE
# =========================
FROM php:8.2-cli

# =========================
# INSTALL SYSTEM DEPENDENCIES
# =========================
RUN apt-get update && apt-get install -y \
    git \
    curl \
    unzip \
    zip \
    libzip-dev \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    nodejs \
    npm \
    && docker-php-ext-install \
    pdo \
    pdo_mysql \
    mbstring \
    zip \
    exif \
    pcntl

# =========================
# INSTALL COMPOSER
# =========================
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# =========================
# WORKDIR
# =========================
WORKDIR /app

# =========================
# COPY PROJECT
# =========================
COPY . .

# =========================
# INSTALL PHP DEPENDENCIES
# =========================
RUN composer install --ignore-platform-reqs --no-interaction --prefer-dist

# =========================
# INSTALL NODE DEPENDENCIES
# =========================
RUN npm install

# =========================
# BUILD FRONTEND ASSETS
# =========================
RUN npm run build

# =========================
# LARAVEL SETUP
# =========================
RUN cp env.example .env || true

RUN php artisan key:generate

# =========================
# EXPOSE PORT
# =========================
EXPOSE 8000

# =========================
# START SERVER
# =========================
CMD ["php", "artisan", "serve", "--host=0.0.0.0", "--port=8000"]