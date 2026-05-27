<?php
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\ReportController;
use App\Http\Controllers\ScannerController;
use App\Http\Controllers\TelegramIntegrationController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return redirect()->route('dashboard');
});

Route::middleware(['auth', 'verified'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');
    Route::get('/scanner/logs', [ScannerController::class, 'logs'])->name('scanner.logs');
    Route::get('/scanner/run', [ScannerController::class, 'run'])->name('scanner.run');
    Route::post('/scanner/run', [ScannerController::class, 'execute'])->name('scanner.execute');
    Route::get('/scanner/logs/{scanRun}', [ScannerController::class, 'show'])->name('scanner.show');
    Route::get('/reports', [ReportController::class, 'index'])->name('reports.index');
    Route::get('/integrations/telegram', [TelegramIntegrationController::class, 'edit'])->name('integrations.telegram.edit');
    Route::put('/integrations/telegram', [TelegramIntegrationController::class, 'update'])->name('integrations.telegram.update');
    Route::post('/integrations/telegram/test', [TelegramIntegrationController::class, 'sendTest'])->name('integrations.telegram.test');
    Route::get('/profile', fn() => view('profile.edit'))->name('profile.edit');
});

require __DIR__.'/auth.php';