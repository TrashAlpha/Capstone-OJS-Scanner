<?php

namespace App\Http\Controllers;

use App\Services\TelegramService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

class TelegramIntegrationController extends Controller
{
    public function edit(Request $request): View
    {
        return view('integrations.telegram', [
            'user' => $request->user(),
            'botUsername' => config('services.telegram.bot_username'),
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
        $user = $request->user();

        if (! $user->telegram_notifications_enabled || ! $user->telegram_chat_id) {
            return redirect()
                ->route('integrations.telegram.edit')
                ->withErrors(['telegram_chat_id' => 'Please save your Telegram Chat ID first.']);
        }

        $sent = $telegram->sendTestMessage($user);

        return redirect()
            ->route('integrations.telegram.edit')
            ->with('status', $sent
                ? 'Test Telegram message sent successfully.'
                : 'Test Telegram message could not be delivered. Make sure you have pressed Start in the bot and that the Chat ID is correct.');
    }
}
