<?php

namespace Tests\Feature;

use App\Models\ScanRun;
use App\Models\User;
use App\Services\TelegramService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class TelegramNotificationTest extends TestCase
{
    use RefreshDatabase;

    public function test_telegram_notification_is_sent_for_connected_user(): void
    {
        Config::set('services.telegram.bot_token', 'test-bot-token');

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
            'https://api.telegram.org/*' => Http::response([
                'ok' => true,
                'result' => ['message_id' => 1],
            ], 200),
        ]);

        $user = User::factory()->create([
            'telegram_chat_id' => '123456789',
            'telegram_notifications_enabled' => true,
        ]);

        $response = $this->actingAs($user)->post('/scanner/run', [
            'ojs_url' => 'http://ojs.test',
            'scan_type' => 'external',
        ]);

        $response->assertRedirect();

        Http::assertSent(fn ($request) => str_contains($request->url(), 'https://api.telegram.org/bottest-bot-token/sendMessage')
            && $request['chat_id'] === '123456789');
    }

    public function test_telegram_service_skips_when_user_not_connected(): void
    {
        Config::set('services.telegram.bot_token', 'test-bot-token');

        Http::fake();

        $user = User::factory()->create([
            'telegram_chat_id' => null,
            'telegram_notifications_enabled' => false,
        ]);

        $scanRun = ScanRun::create([
            'user_id' => $user->id,
            'target_url' => 'http://ojs.test',
            'scan_type' => 'external',
            'status' => 'completed',
            'summary_total_findings' => 0,
            'summary_max_score' => 0,
            'summary_severity' => 'INFORMATIONAL',
            'warnings' => [],
            'scanner_payload' => [],
            'risk_payload' => [],
            'scanned_at' => now(),
        ]);

        $result = app(TelegramService::class)->sendScanSummary($user, $scanRun);

        $this->assertFalse($result);
        Http::assertNothingSent();
    }
}
