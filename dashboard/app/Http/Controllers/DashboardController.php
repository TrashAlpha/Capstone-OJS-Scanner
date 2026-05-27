<?php

namespace App\Http\Controllers;

use App\Models\ScanFinding;
use App\Models\ScanRun;

class DashboardController extends Controller
{
    public function index()
    {
        $logs = ScanFinding::query()
            ->latest('scanned_at')
            ->limit(5)
            ->get();

        $stats = [
            'total' => ScanRun::count(),
            'high' => ScanFinding::whereIn('risk', ['critical', 'high'])->count(),
            'medium' => ScanFinding::where('risk', 'medium')->count(),
            'low' => ScanFinding::whereIn('risk', ['low', 'informational'])->count(),
        ];

        $recentLogs = $logs->map(fn (ScanFinding $log) => [
            'target' => $log->target,
            'type' => $log->type,
            'category' => $log->category,
            'finding' => $log->finding,
            'cvss_score' => $log->cvss_score,
            'risk' => $log->risk,
            'scanned_at' => optional($log->scanned_at)->format('Y-m-d H:i:s') ?? '-',
        ])->all();

        $lastScan = optional(ScanRun::query()->latest('scanned_at')->first()?->scanned_at)->format('Y-m-d H:i:s') ?? 'No scans yet';

        return view('dashboard', compact('stats', 'recentLogs', 'lastScan'));
    }
}
