<?php

namespace App\Http\Controllers;

use App\Services\TelegramService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

class TelegramIntegrationController extends Controller
{
    public function edit(Request $request, TelegramService $telegram): View
    {
        return view('integrations.telegram', [
            'user' => $request->user(),
            'botUsername' => $telegram->getBotUsername(),
            'botTokenPresent' => $telegram->hasBotToken(),
        ]);
    }

    public function update(Request $request): RedirectResponse
    {
        $validated = $request->validate([
            'telegram_chat_id' => ['nullable', 'string', 'max:255'],
        ]);

        $chatId = trim((string) ($validated['telegram_chat_id'] ?? ''));

        $request->user()->update([
            'telegram_chat_id' => $chatId !== '' ? $chatId : null,
            'telegram_notifications_enabled' => $chatId !== '',
        ]);

        return redirect()
            ->route('integrations.telegram.edit')
            ->with('status', $chatId !== ''
                ? 'Telegram notifications have been connected.'
                : 'Telegram notifications have been disconnected.');
    }

    public function sendTest(Request $request, TelegramService $telegram): RedirectResponse
    {
        if (! $telegram->hasBotToken()) {
            return redirect()
                ->route('integrations.telegram.edit')
                ->withErrors(['telegram_chat_id' => 'Bot token belum dikonfigurasi. Pastikan TELEGRAM_BOT_TOKEN sudah diset di environment.']);
        }

        $user = $request->user()?->fresh();

        if (! $user || ! $user->telegram_notifications_enabled || ! $user->telegram_chat_id) {
            return redirect()
                ->route('integrations.telegram.edit')
                ->withErrors(['telegram_chat_id' => 'Simpan Chat ID terlebih dahulu sebelum mengirim test message.']);
        }

        $sent = $telegram->sendTestMessage($user);

        return redirect()
            ->route('integrations.telegram.edit')
            ->with('status', $sent
                ? 'Test Telegram message sent successfully.'
                : 'Test Telegram message could not be delivered. Please verify the Chat ID and make sure you have pressed Start in the bot.');
    }
}
