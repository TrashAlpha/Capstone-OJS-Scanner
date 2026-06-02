<?php

namespace App\Services;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Http;
use RuntimeException;

class RiskEngineService
{
    public function analyze(array $findings): array
    {
        if (empty($findings)) {
            return [
                'summary' => [
                    'total_findings'    => 0,
                    'overall_max_score' => 0.0,
                    'overall_severity'  => 'INFORMATIONAL',
                ],
                'details'           => [],
                'telegram_notified' => false,
            ];
        }

        $response = Http::timeout(30)
            ->asJson()
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
        $findings = [];

        // External scan format: nuclei_results
        foreach ($scanResponse['nuclei_results'] ?? [] as $r) {
            $extracted = $r['extracted_results'] ?? [];
            $findings[] = [
                'name'              => $r['template_name'] ?? $r['template_id'] ?? 'Unknown',
                'cwe_id'            => $r['cwe_id'] ?? 'N/A',
                'cvss_vector'       => $r['cvss_metrics'] ?? '',
                'base_score'        => $r['cvss_score'] ?? $this->mapSeverityToScore($r['severity'] ?? 'info'),
                'extracted_results' => is_array($extracted) ? implode(', ', $extracted) : ($r['description'] ?? ''),
            ];
        }

        // Internal scan format: module_results
        foreach ($scanResponse['module_results'] ?? [] as $moduleResult) {
            $module = $moduleResult['module'] ?? 'unknown';
            foreach ($moduleResult['findings'] ?? [] as $finding) {
                $findings[] = [
                    'name'              => $finding['title'] ?? 'Unknown Vulnerability',
                    'cwe_id'            => $this->guessCweId($module, $finding),
                    'cvss_vector'       => data_get($finding, 'extra.cvss_vector', ''),
                    'base_score'        => data_get($finding, 'extra.base_score') ?? $this->mapSeverityToScore($finding['severity'] ?? 'info'),
                    'extracted_results' => $finding['evidence'] ?? ($finding['description'] ?? 'No evidence found'),
                ];
            }
        }

        return $findings;
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
