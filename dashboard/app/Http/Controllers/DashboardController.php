<?php

namespace App\Http\Controllers;

use App\Models\ScanFinding;
use App\Models\ScanRun;

class DashboardController extends Controller
{
    public function index()
    {
        $stats = [
            'total'  => ScanRun::count(),
            'high'   => ScanFinding::whereIn('risk', ['critical', 'high'])->count(),
            'medium' => ScanFinding::where('risk', 'medium')->count(),
            'low'    => ScanFinding::whereIn('risk', ['low', 'informational'])->count(),
        ];

        $runningScans  = ScanRun::where('status', 'running')->latest('scanned_at')->get();
        $completedScans = ScanRun::where('status', 'completed')->latest('scanned_at')->limit(10)->get();

        return view('dashboard', compact('stats', 'runningScans', 'completedScans'));
    }
}
