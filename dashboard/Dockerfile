FROM php:8.2-cli

WORKDIR /app

COPY . .

RUN apt-get update && apt-get install -y \
    unzip \
    git \
    libzip-dev

RUN docker-php-ext-install pdo pdo_mysql

ENV PORT=8080

EXPOSE 8080

CMD php artisan serve --host=0.0.0.0 --port=$PORT