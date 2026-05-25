<?php

namespace App\Http\Controllers;

use App\Models\ScanFinding;
use App\Models\ScanRun;
use App\Services\RiskEngineService;
use App\Services\ScannerService;
use App\Services\TelegramService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Throwable;

class ScannerController extends Controller
{
    public function logs(Request $request)
    {
        $query = ScanFinding::query()->with('scanRun')->latest('scanned_at');

        if ($request->filled('risk')) {
            $query->where('risk', strtolower((string) $request->string('risk')));
        }

        if ($request->filled('type')) {
            $query->where('type', strtolower((string) $request->string('type')));
        }

        if ($request->filled('search')) {
            $search = (string) $request->string('search');
            $query->where(function ($q) use ($search): void {
                $q->where('target', 'like', "%{$search}%")
                    ->orWhere('finding', 'like', "%{$search}%")
                    ->orWhere('category', 'like', "%{$search}%");
            });
        }

        $logs = $query->get()->map(function (ScanFinding $log): array {
            return [
                'id' => $log->id,
                'scan_run_id' => $log->scan_run_id,
                'target' => $log->target,
                'type' => $log->type,
                'category' => $log->category,
                'finding' => $log->finding,
                'cvss_score' => $log->cvss_score,
                'risk' => $log->risk,
                'scanned_at' => optional($log->scanned_at)->format('Y-m-d H:i:s') ?? '-',
            ];
        })->all();

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

    public function execute(Request $request, ScannerService $scanner, RiskEngineService $riskEngine, TelegramService $telegram): RedirectResponse
    {
        $validated = $request->validate([
            'ojs_url' => ['required', 'url'],
            'scan_type' => ['required', 'in:external,internal,full'],
            'admin_username' => ['nullable', 'string', 'max:255'],
            'admin_password' => ['nullable', 'string', 'max:255'],
        ]);

        try {
            $scanResponse = $scanner->runScan(
                $validated['ojs_url'],
                $validated['scan_type'],
                $validated['admin_username'] ?? null,
                $validated['admin_password'] ?? null,
            );

            $analysis = $riskEngine->analyzeScannerResults($scanResponse);
            $scanRun = $this->storeScanRun($validated, $scanResponse, $analysis);
            $telegramSent = $request->user() ? $telegram->sendScanSummary($request->user(), $scanRun) : false;

            $message = 'Scan completed successfully.';
            if ($telegramSent) {
                $message .= ' Telegram notification sent.';
            } elseif ($request->user()?->telegram_notifications_enabled) {
                $message .= ' Telegram notification could not be delivered.';
            }

            if (! empty($scanResponse['warnings'])) {
                $message .= ' Warning: '.implode(' ', $scanResponse['warnings']);
            }

            return redirect()->route('scanner.show', $scanRun)->with('status', $message);
        } catch (Throwable $e) {
            return redirect()
                ->route('scanner.run')
                ->withInput()
                ->withErrors(['scan' => $e->getMessage()]);
        }
    }

    private function storeScanRun(array $validated, array $scanResponse, array $analysis): ScanRun
    {
        $scannedAt = $scanResponse['generated_at'] ?? now()->toIso8601String();

        $scanRun = ScanRun::create([
            'user_id' => auth()->id(),
            'target_url' => $scanResponse['target_url'] ?? $validated['ojs_url'],
            'scan_type' => strtolower($scanResponse['scan_type'] ?? $validated['scan_type']),
            'status' => 'completed',
            'summary_total_findings' => $analysis['summary']['total_findings'] ?? 0,
            'summary_max_score' => $analysis['summary']['overall_max_score'] ?? 0,
            'summary_severity' => $analysis['summary']['overall_severity'] ?? 'INFORMATIONAL',
            'warnings' => $scanResponse['warnings'] ?? [],
            'scanner_payload' => $scanResponse,
            'risk_payload' => $analysis,
            'scanned_at' => $scannedAt,
        ]);

        $scanRun->findings()->createMany($this->buildFindings($scanResponse, $analysis));

        return $scanRun;
    }

    private function buildFindings(array $scanResponse, array $analysis): array
    {
        $target = $scanResponse['target_url'] ?? 'Unknown Target';
        $type = strtolower($scanResponse['scan_type'] ?? 'external');
        $scannedAt = $scanResponse['generated_at'] ?? now()->toIso8601String();

        return collect($analysis['details'] ?? [])->map(fn (array $item) => [
            'target' => $target,
            'type' => $type,
            'category' => $item['category'] ?? '-',
            'finding' => $item['vulnerability_name'] ?? '-',
            'cvss_score' => $item['cvss_score'] ?? 0,
            'risk' => strtolower($item['severity'] ?? 'informational'),
            'scanned_at' => $scannedAt,
            'evidence' => $item['evidence'] ?? '-',
            'cwe_id' => $item['cwe_id'] ?? 'N/A',
            'cvss_vector' => $item['cvss_vector'] ?? '',
        ])->all();
    }
}
