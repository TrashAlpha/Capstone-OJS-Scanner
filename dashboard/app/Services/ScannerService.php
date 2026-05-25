<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use RuntimeException;

class ScannerService
{
    public function runScan(string $targetUrl, string $scanType = 'external', ?string $username = null, ?string $password = null): array
    {
        $response = Http::timeout(60)
            ->acceptJson()
            ->post(config('services.scanner.url').'/scan', [
                'target_url' => $targetUrl,
                'scan_type' => $scanType,
                'admin_username' => $username,
                'admin_password' => $password,
            ]);

        if (! $response->successful()) {
            throw new RuntimeException('Scanner request failed: '.$response->body());
        }

        return $response->json();
    }
}
