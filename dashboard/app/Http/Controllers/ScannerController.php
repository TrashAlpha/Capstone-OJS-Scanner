<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;

class ScannerController extends Controller
{
    public function logs(Request $request)
    {
        $logs = [];
        return view('scanner.logs', compact('logs'));
    }

    public function run()
    {
        return view('scanner.run');
    }
}