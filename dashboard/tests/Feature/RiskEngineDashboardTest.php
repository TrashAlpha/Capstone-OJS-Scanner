<?php

namespace Tests\Feature;

use App\Models\ScanFinding;
use App\Models\ScanRun;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class RiskEngineDashboardTest extends TestCase
{
    use RefreshDatabase;

    public function test_user_can_run_scan_and_persist_results(): void
    {
        Http::fake([
            'http://scanner:5000/scan' => Http::response([
                'target_url' => 'http://ojs.test',
                'scan_type' => 'external',
                'generated_at' => '2026-05-25T12:00:00+00:00',
                'warnings' => [],
                'results' => [
                    [
                        'module' => 'version_scanner',
                        'findings' => [
                            [
                                'title' => 'CVE-2021-27183 — OJS 3.2.1',
                                'severity' => 'high',
                                'description' => 'Stored XSS via journal title field',
                                'evidence' => 'Version 3.2.1 vulnerable',
                            ],
                        ],
                        'raw' => [],
                    ],
                ],
            ], 200),
            'http://risk-engine:5000/analyze' => Http::response([
                'summary' => [
                    'total_findings' => 1,
                    'overall_max_score' => 8.0,
                    'overall_severity' => 'HIGH',
                ],
                'details' => [
                    [
                        'vulnerability_name' => 'CVE-2021-27183 — OJS 3.2.1',
                        'cwe_id' => 'CWE-79',
                        'category' => 'Cross-site Scripting (XSS)',
                        'cvss_score' => 8.0,
                        'cvss_vector' => '',
                        'severity' => 'HIGH',
                        'evidence' => 'Version 3.2.1 vulnerable',
                    ],
                ],
            ], 200),
        ]);

        $user = User::factory()->create();

        $response = $this->actingAs($user)->post('/scanner/run', [
            'ojs_url' => 'http://ojs.test',
            'scan_type' => 'external',
        ]);

        $scanRun = ScanRun::first();

        $response->assertRedirect(route('scanner.show', $scanRun, absolute: false));
        $this->assertDatabaseHas('scan_runs', [
            'target_url' => 'http://ojs.test',
            'scan_type' => 'external',
            'summary_total_findings' => 1,
            'summary_severity' => 'HIGH',
        ]);
        $this->assertDatabaseHas('scan_findings', [
            'scan_run_id' => $scanRun->id,
            'finding' => 'CVE-2021-27183 — OJS 3.2.1',
            'risk' => 'high',
            'cwe_id' => 'CWE-79',
        ]);
    }

    public function test_dashboard_and_logs_show_persisted_results(): void
    {
        $scanRun = ScanRun::create([
            'target_url' => 'http://ojs.test',
            'scan_type' => 'external',
            'status' => 'completed',
            'summary_total_findings' => 1,
            'summary_max_score' => 6.1,
            'summary_severity' => 'MEDIUM',
            'warnings' => [],
            'scanner_payload' => [],
            'risk_payload' => [],
            'scanned_at' => '2026-05-25 12:00:00',
        ]);

        ScanFinding::create([
            'scan_run_id' => $scanRun->id,
            'target' => 'http://ojs.test',
            'type' => 'external',
            'category' => 'Cross-site Scripting (XSS)',
            'finding' => 'Stored XSS on journal title field',
            'cvss_score' => 6.1,
            'risk' => 'medium',
            'scanned_at' => '2026-05-25 12:00:00',
            'evidence' => 'Script payload reflected',
            'cwe_id' => 'CWE-79',
            'cvss_vector' => '',
        ]);

        $user = User::factory()->create();

        $dashboard = $this->actingAs($user)->get('/dashboard');
        $dashboard->assertStatus(200);
        $dashboard->assertSee('Stored XSS on journal title field');

        $logs = $this->actingAs($user)->get('/scanner/logs');
        $logs->assertStatus(200);
        $logs->assertSee('http://ojs.test');
        $logs->assertSee('Stored XSS on journal title field');

        $detail = $this->actingAs($user)->get(route('scanner.show', $scanRun));
        $detail->assertStatus(200);
        $detail->assertSee('Cross-site Scripting (XSS)');
        $detail->assertSee('Script payload reflected');
    }
}
