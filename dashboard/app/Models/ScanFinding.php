<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

#[Fillable([
    'scan_run_id',
    'target',
    'type',
    'category',
    'finding',
    'cvss_score',
    'risk',
    'scanned_at',
    'evidence',
    'cwe_id',
    'cvss_vector',
])]
class ScanFinding extends Model
{
    use HasFactory;

    public function scanRun(): BelongsTo
    {
        return $this->belongsTo(ScanRun::class);
    }

    protected function casts(): array
    {
        return [
            'scanned_at' => 'datetime',
            'cvss_score' => 'float',
        ];
    }
}
