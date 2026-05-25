<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

#[Fillable([
    'user_id',
    'target_url',
    'scan_type',
    'status',
    'summary_total_findings',
    'summary_max_score',
    'summary_severity',
    'warnings',
    'scanner_payload',
    'risk_payload',
    'scanned_at',
])]
class ScanRun extends Model
{
    use HasFactory;

    public function findings(): HasMany
    {
        return $this->hasMany(ScanFinding::class);
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    protected function casts(): array
    {
        return [
            'warnings' => 'array',
            'scanner_payload' => 'array',
            'risk_payload' => 'array',
            'scanned_at' => 'datetime',
            'summary_max_score' => 'float',
        ];
    }
}
