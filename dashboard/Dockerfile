FROM php:8.2-cli

WORKDIR /app
COPY . .

RUN apt-get update

CMD ["php", "artisan", "serve", "--host=0.0.0.0", "--port=8000"]
