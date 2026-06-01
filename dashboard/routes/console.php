<?php

use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

// Automasi scan terjadwal
Schedule::command('scans:dispatch-due')->everyMinute()->withoutOverlapping();
Schedule::command('scans:finalize')->everyMinute()->withoutOverlapping();
