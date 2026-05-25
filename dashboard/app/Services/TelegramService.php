<?php

namespace App\Services;

use App\Models\ScanRun;
use App\Models\User;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class TelegramService
{
    public function sendScanSummary(User $user, ScanRun $scanRun): bool
    {
        if (! $this->canSendToUser($user)) {
            return false;
        }

        return $this->sendMessage($user->telegram_chat_id, $this->buildScanSummaryMessage($scanRun), [
            'user_id' => $user->id,
            'scan_run_id' => $scanRun->id,
        ]);
    }

    public function sendTestMessage(User $user): bool
    {
        if (! $this->canSendToUser($user)) {
            return false;
        }

        return $this->sendMessage($user->telegram_chat_id, implode("\n", [
            'Telegram connection test successful.',
            '',
            'You will receive future OJS scan alerts in this chat.',
            'If you ever need your Chat ID again, send /start to the bot.',
        ]), [
            'user_id' => $user->id,
            'type' => 'test',
        ]);
    }

    public function sendMessage(string $chatId, string $message, array $context = []): bool
    {
        $botToken = config('services.telegram.bot_token');

        if (! $botToken || $chatId === '') {
            return false;
        }

        $response = Http::timeout(15)
            ->asForm()
            ->post("https://api.telegram.org/bot{$botToken}/sendMessage", [
                'chat_id' => $chatId,
                'text' => $message,
            ]);

        if (! $response->successful()) {
            Log::warning('Telegram notification failed', array_merge($context, [
                'chat_id' => $chatId,
                'response' => $response->body(),
            ]));

            return false;
        }

        return true;
    }

    private function canSendToUser(User $user): bool
    {
        return (bool) config('services.telegram.bot_token')
            && $user->telegram_notifications_enabled
            && filled($user->telegram_chat_id);
    }

    private function buildScanSummaryMessage(ScanRun $scanRun): string
    {
        $findings = $scanRun->findings()
            ->latest('cvss_score')
            ->limit(3)
            ->get();

        $lines = [
            'OJS Scan Completed',
            '',
            'Target: '.$scanRun->target_url,
            'Type: '.strtoupper($scanRun->scan_type),
            'Findings: '.$scanRun->summary_total_findings,
            'Max CVSS: '.number_format((float) $scanRun->summary_max_score, 1),
            'Severity: '.$scanRun->summary_severity,
        ];

        if ($findings->isNotEmpty()) {
            $lines[] = '';
            $lines[] = 'Top findings:';

            foreach ($findings as $finding) {
                $lines[] = '- '.$finding->finding.' ['.strtoupper($finding->risk).']';
            }
        }

        if (! empty($scanRun->warnings)) {
            $lines[] = '';
            $lines[] = 'Warnings: '.implode(' ', $scanRun->warnings);
        }

        return implode("\n", $lines);
    }
}
