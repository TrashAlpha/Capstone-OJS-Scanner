<?php

namespace App\Http\Controllers;

use App\Models\ScanLog;
use App\Models\ScanRun;
use App\Services\ScanRunner;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Throwable;

class ScannerController extends Controller
{
    public function logs(Request $request)
    {
        $query = ScanLog::latest('created_at');

        if ($request->filled('search')) {
            $query->where('target_url', 'like', '%'.(string) $request->string('search').'%');
        }

        if ($request->filled('type')) {
            $query->where('scan_type', (string) $request->string('type'));
        }

        if ($request->filled('status')) {
            $query->where('status', (string) $request->string('status'));
        }

        $logs = $query->limit(100)->get();

        return view('scanner.logs', compact('logs'));
    }

    public function run()
    {
        return view('scanner.run');
    }

    public function show(ScanRun $scanRun)
    {
        $scanRun->load('findings', 'user');

        return view('scanner.show', [
            'scanRun' => $scanRun,
            'findings' => $scanRun->findings()->latest('cvss_score')->get(),
        ]);
    }

    public function execute(Request $request, ScanRunner $runner): RedirectResponse
    {
        $validated = $request->validate([
            'ojs_url'        => ['required', 'url'],
            'scan_type'      => ['required', 'in:external,internal,full'],
            'admin_username' => ['nullable', 'string', 'max:255'],
            'admin_password' => ['nullable', 'string', 'max:255'],
        ]);

        try {
            $runner->dispatch(
                $validated['ojs_url'],
                $validated['scan_type'],
                $validated['admin_username'] ?? null,
                $validated['admin_password'] ?? null,
                auth()->id(),
            );

            return redirect()->route('dashboard')
                ->with('status', 'Scan dimulai untuk '.$validated['ojs_url'].'. Hasil akan muncul otomatis di dashboard.');
        } catch (Throwable $e) {
            return redirect()
                ->route('scanner.run')
                ->withInput()
                ->withErrors(['scan' => $e->getMessage()]);
        }
    }

    public function poll(ScanRun $scanRun, ScanRunner $runner): \Illuminate\Http\JsonResponse
    {
        if ($scanRun->status !== 'running') {
            return response()->json(['status' => $scanRun->status]);
        }

        $status = $runner->finalize($scanRun);

        if ($status === 'completed') {
            return response()->json([
                'status'   => 'completed',
                'redirect' => route('scanner.show', $scanRun),
            ]);
        }

        if ($status === 'failed') {
            return response()->json([
                'status' => 'failed',
                'error'  => 'Scan gagal',
            ]);
        }

        return response()->json(['status' => 'running']);
    }
}
