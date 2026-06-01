<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ScanLog extends Model
{
    protected $table = 'scan_logs';

    public $timestamps = false;

    protected $casts = [
        'result_json' => 'array',
        'created_at'  => 'datetime',
        'completed_at' => 'datetime',
    ];
}
