<?php

namespace App\Services;

use App\Models\ScanLog;
use App\Models\ScanRun;
use App\Models\ScanSchedule;
use App\Models\User;
use Illuminate\Support\Facades\Log;
use Throwable;

class ScanRunner
{
    public function __construct(
        private ScannerService $scanner,
        private RiskEngineService $riskEngine,
    ) {}

    /**
     * Trigger scan (non-blocking) dan buat record ScanRun(status=running).
     * Dipakai oleh form manual maupun scheduler.
     */
    public function dispatch(
        string $targetUrl,
        string $scanType,
        ?string $username = null,
        ?string $password = null,
        ?int $userId = null,
        ?ScanSchedule $schedule = null,
    ): ScanRun {
        $scanId = $this->scanner->triggerScan($targetUrl, $scanType, $username, $password);

        return ScanRun::create([
            'user_id'         => $userId,
            'target_url'      => $targetUrl,
            'scan_type'       => $scanType,
            'status'          => 'running',
            'scanner_payload' => [
                'scan_id'          => $scanId,
                'scan_schedule_id' => $schedule?->id,
            ],
            'scanned_at'      => now(),
        ]);
    }

    /**
     * Finalisasi sebuah ScanRun yang masih running dengan membaca status dari ScanLog
     * (DB bersama dengan scanner). Mengembalikan status akhir: completed|failed|running.
     *
     * Aman dipanggil berkali-kali: hanya beraksi saat status masih 'running'.
     */
    public function finalize(ScanRun $scanRun): string
    {
        if ($scanRun->status !== 'running') {
            return $scanRun->status;
        }

        $scanId = $scanRun->scanner_payload['scan_id'] ?? null;
        if (! $scanId) {
            $scanRun->update(['status' => 'failed']);

            return 'failed';
        }

        $logRow = ScanLog::find($scanId);
        if (! $logRow) {
            return 'running';
        }

        if ($logRow->status === 'completed') {
            $result = is_array($logRow->result_json) ? $logRow->result_json : [];

            try {
                $analysis = $this->riskEngine->analyzeScannerResults($result);
            } catch (Throwable $e) {
                Log::warning('Risk Engine analysis failed during finalize', ['error' => $e->getMessage(), 'scan_run_id' => $scanRun->id]);
                $analysis = [];
            }

            $scanRun->update([
                'status'                 => 'completed',
                'summary_total_findings' => $analysis['summary']['total_findings'] ?? 0,
                'summary_max_score'      => $analysis['summary']['overall_max_score'] ?? 0,
                'summary_severity'       => $analysis['summary']['overall_severity'] ?? 'INFORMATIONAL',
                'warnings'               => $result['warnings'] ?? [],
                'scanner_payload'        => $result,
                'risk_payload'           => $analysis,
                'scanned_at'             => $logRow->completed_at ?? now(),
            ]);

            $scanRun->findings()->createMany($this->buildFindings($result, $analysis));

            $this->notify($scanRun);

            return 'completed';
        }

        if ($logRow->status === 'failed') {
            $scanRun->update(['status' => 'failed']);

            return 'failed';
        }

        return 'running';
    }

    private function notify(ScanRun $scanRun): void
    {
        try {
            $notifyUser = $scanRun->user ?? User::find($scanRun->user_id);
            if ($notifyUser) {
                app(TelegramService::class)->sendHighCriticalAlert($notifyUser, $scanRun);
            } else {
                Log::warning('Telegram alert skipped: user not found', ['scan_run_id' => $scanRun->id, 'user_id' => $scanRun->user_id]);
            }
        } catch (Throwable $e) {
            Log::warning('Telegram alert failed', ['error' => $e->getMessage(), 'scan_run_id' => $scanRun->id]);
        }
    }

    public function buildFindings(array $scanResponse, array $analysis): array
    {
        $target = $scanResponse['target_url'] ?? 'Unknown Target';
        $type = strtolower($scanResponse['scan_type'] ?? 'external');
        $scannedAt = $scanResponse['generated_at'] ?? now()->toIso8601String();

        return collect($analysis['details'] ?? [])->map(fn (array $item) => [
            'target'      => $target,
            'type'        => $type,
            'category'    => $item['category'] ?? '-',
            'finding'     => $item['vulnerability_name'] ?? '-',
            'cvss_score'  => $item['cvss_score'] ?? 0,
            'risk'        => strtolower($item['severity'] ?? 'informational'),
            'scanned_at'  => $scannedAt,
            'evidence'    => $item['evidence'] ?? '-',
            'cwe_id'      => $item['cwe_id'] ?? 'N/A',
            'cvss_vector' => $item['cvss_vector'] ?? '',
        ])->all();
    }
}
