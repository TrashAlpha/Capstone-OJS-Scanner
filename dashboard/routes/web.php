<?php
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\ScannerController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return redirect()->route('dashboard');
});

Route::middleware(['auth', 'verified'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');
    Route::get('/scanner/logs', [ScannerController::class, 'logs'])->name('scanner.logs');
    Route::get('/scanner/run', [ScannerController::class, 'run'])->name('scanner.run');
    Route::get('/reports', fn() => view('reports.index'))->name('reports.index');
    Route::get('/profile', fn() => view('profile.edit'))->name('profile.edit');
});

require __DIR__.'/auth.php';