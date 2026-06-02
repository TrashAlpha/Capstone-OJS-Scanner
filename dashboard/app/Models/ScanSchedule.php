<?php

namespace App\Models;

use Cron\CronExpression;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

#[Fillable([
    'user_id',
    'name',
    'target_url',
    'scan_type',
    'admin_username',
    'admin_password',
    'frequency',
    'cron_expression',
    'timezone',
    'is_active',
    'last_run_at',
    'next_run_at',
    'last_scan_run_id',
])]
class ScanSchedule extends Model
{
    use HasFactory;

    protected function casts(): array
    {
        return [
            'admin_password' => 'encrypted',
            'is_active'      => 'boolean',
            'last_run_at'    => 'datetime',
            'next_run_at'    => 'datetime',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function lastScanRun(): BelongsTo
    {
        return $this->belongsTo(ScanRun::class, 'last_scan_run_id');
    }

    /**
     * Hitung waktu eksekusi berikutnya berdasarkan cron_expression dalam timezone jadwal.
     */
    public function computeNextRunAt(): Carbon
    {
        $tz = $this->timezone ?: config('app.timezone', 'UTC');
        $next = (new CronExpression($this->cron_expression))
            ->getNextRunDate(Carbon::now($tz), 0, false, $tz);

        return Carbon::instance($next);
    }

    public function requiresCredentials(): bool
    {
        return in_array($this->scan_type, ['internal', 'full'], true);
    }
}
