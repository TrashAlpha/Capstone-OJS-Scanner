<?php

namespace App\Http\Controllers;

class DashboardController extends Controller
{
    public function index()
    {
        $stats = ['total'=>0, 'high'=>0, 'medium'=>0, 'low'=>0];
        $recentLogs = [];
        $lastScan = 'No scans yet';
        return view('dashboard', compact('stats', 'recentLogs', 'lastScan'));
    }
}