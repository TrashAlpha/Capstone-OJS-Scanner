<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class TelegramIntegrationTest extends TestCase
{
    use RefreshDatabase;

    public function test_telegram_settings_page_can_be_rendered(): void
    {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->get('/integrations/telegram');

        $response->assertStatus(200);
        $response->assertSee('Telegram Chat ID');
        $response->assertSee('Start');
        $response->assertSee('No webhook needed');
    }

    public function test_user_can_save_telegram_chat_id(): void
    {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->put('/integrations/telegram', [
            'telegram_chat_id' => '123456789',
        ]);

        $response->assertRedirect(route('integrations.telegram.edit', absolute: false));
        $this->assertDatabaseHas('users', [
            'id' => $user->id,
            'telegram_chat_id' => '123456789',
            'telegram_notifications_enabled' => true,
        ]);
    }

    public function test_user_can_send_test_telegram_message(): void
    {
        Config::set('services.telegram.bot_token', 'test-bot-token');

        Http::fake([
            'https://api.telegram.org/*' => Http::response(['ok' => true], 200),
        ]);

        $user = User::factory()->create([
            'telegram_chat_id' => '123456789',
            'telegram_notifications_enabled' => true,
        ]);

        $response = $this->actingAs($user)->post('/integrations/telegram/test');

        $response->assertRedirect(route('integrations.telegram.edit', absolute: false));
        Http::assertSent(fn ($request) => str_contains($request->url(), 'https://api.telegram.org/bottest-bot-token/sendMessage')
            && $request['chat_id'] === '123456789');
    }
}
