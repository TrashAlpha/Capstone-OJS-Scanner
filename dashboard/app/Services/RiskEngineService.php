<?php

namespace App\Services;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Http;
use RuntimeException;

class RiskEngineService
{
    public function analyze(array $findings): array
    {
        $response = Http::timeout(30)
            ->acceptJson()
            ->post(config('services.risk_engine.url').'/analyze', $findings);

        if (! $response->successful()) {
            throw new RuntimeException('Risk Engine request failed: '.$response->body());
        }

        return $response->json();
    }

    public function analyzeScannerResults(array $scanResponse): array
    {
        return $this->analyze($this->normalizeScannerResults($scanResponse));
    }

    public function normalizeScannerResults(array $scanResponse): array
    {
        return collect($scanResponse['results'] ?? [])
            ->flatMap(function (array $moduleResult): array {
                $module = $moduleResult['module'] ?? 'unknown';

                return collect($moduleResult['findings'] ?? [])
                    ->map(fn (array $finding) => [
                        'name' => $finding['title'] ?? 'Unknown Vulnerability',
                        'cwe_id' => $this->guessCweId($module, $finding),
                        'cvss_vector' => data_get($finding, 'extra.cvss_vector', ''),
                        'base_score' => data_get($finding, 'extra.base_score') ?? $this->mapSeverityToScore($finding['severity'] ?? 'info'),
                        'extracted_results' => $finding['evidence'] ?? ($finding['description'] ?? 'No evidence found'),
                    ])
                    ->all();
            })
            ->values()
            ->all();
    }

    private function mapSeverityToScore(string $severity): float
    {
        return match (strtolower($severity)) {
            'critical' => 9.8,
            'high' => 8.0,
            'medium' => 5.5,
            'low' => 3.1,
            default => 0.0,
        };
    }

    private function guessCweId(string $module, array $finding): string
    {
        $text = strtolower(implode(' ', array_filter([
            $module,
            $finding['title'] ?? null,
            $finding['description'] ?? null,
            $finding['evidence'] ?? null,
        ])));

        return match (true) {
            str_contains($text, 'sql injection') => 'CWE-89',
            str_contains($text, 'xss') || str_contains($text, 'cross-site scripting') => 'CWE-79',
            str_contains($text, 'path traversal') || str_contains($text, 'directory traversal') => 'CWE-22',
            str_contains($text, 'file upload') => 'CWE-434',
            str_contains($text, 'idor') => 'CWE-639',
            str_contains($text, 'access control') => 'CWE-284',
            str_contains($text, 'header') || str_contains($text, 'server') || str_contains($text, 'version') || str_contains($text, 'expos') => 'CWE-200',
            default => 'N/A',
        };
    }
}
