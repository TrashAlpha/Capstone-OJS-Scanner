<?php

namespace App\Providers;

use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Laravel dilayani di sub-path /dashboard di belakang NGINX yang
        // memotong prefix tersebut. Paksa semua URL yang di-generate (login,
        // redirect, asset) memakai root dari APP_URL agar menyertakan prefix
        // /dashboard yang benar — tanpa ini redirect login bocor ke OJS.
        if ($url = config('app.url')) {
            URL::forceRootUrl($url);

            if (str_starts_with($url, 'https://')) {
                URL::forceScheme('https');
            }
        }
    }
}
