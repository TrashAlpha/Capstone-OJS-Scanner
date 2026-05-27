<?php

namespace App\Services;

use App\Models\ScanRun;
use App\Models\User;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class TelegramService
{
    public function getBotUsername(): ?string
    {
        return $this->resolveSetting('bot_username');
    }

    public function hasBotToken(): bool
    {
        return filled($this->getBotToken());
    }

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
            Log::info('Telegram test skipped', [
                'user_id' => $user->id,
                'enabled' => $user->telegram_notifications_enabled,
                'chat_id_present' => filled($user->telegram_chat_id),
                'bot_token_present' => $this->hasBotToken(),
            ]);

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
        $botToken = $this->getBotToken();

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
                'status' => $response->status(),
                'response' => $response->body(),
            ]));

            return false;
        }

        return true;
    }

    private function canSendToUser(User $user): bool
    {
        return $this->hasBotToken()
            && $user->telegram_notifications_enabled
            && filled($user->telegram_chat_id);
    }

    private function getBotToken(): ?string
    {
        return $this->resolveSetting('bot_token');
    }

    private function resolveSetting(string $key): ?string
    {
        $configValue = config("services.telegram.{$key}");
        if (filled($configValue)) {
            return (string) $configValue;
        }

        $envKey = 'TELEGRAM_'.strtoupper($key);
        $runtimeValue = getenv($envKey) ?: ($_ENV[$envKey] ?? null) ?: ($_SERVER[$envKey] ?? null);

        return filled($runtimeValue) ? (string) $runtimeValue : null;
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
