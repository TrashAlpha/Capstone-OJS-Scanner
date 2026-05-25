<?php

namespace App\Http\Controllers;

use App\Models\ScanRun;

class ReportController extends Controller
{
    public function index()
    {
        $scanRuns = ScanRun::query()->latest('scanned_at')->get();

        return view('reports.index', compact('scanRuns'));
    }
}
