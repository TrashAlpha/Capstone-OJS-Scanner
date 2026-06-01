<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use RuntimeException;

class ScannerService
{
    private string $baseUrl;

    public function __construct()
    {
        $this->baseUrl = config('services.scanner.url');
    }

    public function runScan(string $targetUrl, string $scanType = 'external', ?string $username = null, ?string $password = null): array
    {
        return match ($scanType) {
            'internal' => $this->triggerAndWait('/scan/internal', [
                'target_url' => $targetUrl,
                'username'   => $username,
                'password'   => $password,
            ]),
            'full' => $this->triggerAndWait('/scan/full', [
                'target_url'   => $targetUrl,
                'scan_profile' => 'general',
                'username'     => $username,
                'password'     => $password,
            ]),
            default => $this->triggerAndWait('/scan', [
                'target_url'   => $targetUrl,
                'scan_profile' => 'general',
            ]),
        };
    }

    /**
     * Trigger scan tanpa menunggu hasil (non-blocking).
     * Kembalikan scan_id dari scanner service.
     */
    public function triggerScan(string $targetUrl, string $scanType = 'external', ?string $username = null, ?string $password = null): int
    {
        return match ($scanType) {
            'internal' => $this->triggerOnly('/scan/internal', [
                'target_url' => $targetUrl,
                'username'   => $username,
                'password'   => $password,
            ]),
            'full' => $this->triggerOnly('/scan/full', [
                'target_url'   => $targetUrl,
                'scan_profile' => 'general',
                'username'     => $username,
                'password'     => $password,
            ]),
            default => $this->triggerOnly('/scan', [
                'target_url'   => $targetUrl,
                'scan_profile' => 'general',
            ]),
        };
    }

    private function triggerOnly(string $endpoint, array $payload): int
    {
        $response = Http::timeout(30)
            ->acceptJson()
            ->post($this->baseUrl.$endpoint, $payload);

        if (! $response->successful()) {
            throw new RuntimeException('Scanner request failed: '.$response->body());
        }

        $scanId = $response->json('scan_id');

        if (! $scanId) {
            throw new RuntimeException('Scanner did not return a scan_id. Response: '.$response->body());
        }

        return (int) $scanId;
    }

    private function triggerAndWait(string $endpoint, array $payload): array
    {
        $response = Http::timeout(30)
            ->acceptJson()
            ->post($this->baseUrl.$endpoint, $payload);

        if (! $response->successful()) {
            throw new RuntimeException('Scanner request failed: '.$response->body());
        }

        $scanId = $response->json('scan_id');

        if (! $scanId) {
            throw new RuntimeException('Scanner did not return a scan_id. Response: '.$response->body());
        }

        return $this->pollScanCompletion((int) $scanId);
    }

    private function pollScanCompletion(int $scanId, int $maxSeconds = 300): array
    {
        $deadline = time() + $maxSeconds;

        while (time() < $deadline) {
            sleep(5);

            $response = Http::timeout(15)
                ->acceptJson()
                ->get($this->baseUrl.'/scans/'.$scanId);

            if (! $response->successful()) {
                continue;
            }

            $data   = $response->json();
            $status = $data['status'] ?? 'running';

            if ($status === 'completed') {
                $resultJson = $data['result_json'] ?? null;

                if (is_string($resultJson)) {
                    $resultJson = json_decode($resultJson, true) ?? [];
                }

                return is_array($resultJson) ? $resultJson : $data;
            }

            if ($status === 'failed') {
                throw new RuntimeException('Scan failed: '.($data['error_message'] ?? 'Unknown error'));
            }
        }

        throw new RuntimeException("Scan timed out after {$maxSeconds} seconds (scan_id={$scanId})");
    }

}
