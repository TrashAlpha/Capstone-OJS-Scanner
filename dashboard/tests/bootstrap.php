<?php

/*
 | -----------------------------------------------------------------------------
 | Paksa environment PENGUJIAN sebelum framework Laravel boot.
 | -----------------------------------------------------------------------------
 |
 | docker-compose menyetel APP_ENV=local, DB_CONNECTION=mysql, APP_URL=.../dashboard
 | sebagai environment variable CONTAINER. Atribut <env force="true"> di phpunit.xml
 | TIDAK menimpa process env tersebut, sehingga `php artisan test` di dalam container
 | bisa berjalan terhadap database "appdb" sungguhan — dan trait RefreshDatabase akan
 | MENGHAPUS (drop) seluruh tabel data produksi.
 |
 | Menyetel process env di sini (putenv + superglobal) dijalankan SEBELUM autoload &
 | sebelum Laravel membaca environment, sehingga pengujian SELALU memakai SQLite
 | in-memory dan tidak pernah menyentuh appdb.
 */

$overrides = [
    'APP_ENV'       => 'testing',
    'APP_URL'       => 'http://localhost',
    'DB_CONNECTION' => 'sqlite',
    'DB_DATABASE'   => ':memory:',
    'DB_HOST'       => '127.0.0.1',
];

foreach ($overrides as $key => $value) {
    putenv("{$key}={$value}");
    $_ENV[$key] = $value;
    $_SERVER[$key] = $value;
}

require __DIR__.'/../vendor/autoload.php';
