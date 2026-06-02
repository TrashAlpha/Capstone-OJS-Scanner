<?php

namespace Tests\Feature;

use App\Models\ScanRun;
use App\Models\ScanSchedule;
use App\Models\User;
use App\Support\CronBuilder;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class ScanScheduleTest extends TestCase
{
    use RefreshDatabase;

    public function test_cron_builder_produces_expected_expressions(): void
    {
        $this->assertSame('30 * * * *', CronBuilder::build('hourly', '09:30'));
        $this->assertSame('30 9 * * *', CronBuilder::build('daily', '09:30'));
        $this->assertSame('0 2 * * 1', CronBuilder::build('weekly', '02:00', 1));
        $this->assertSame('15 8 5 * *', CronBuilder::build('monthly', '08:15', null, 5));
    }

    public function test_user_can_create_schedule_via_dashboard(): void
    {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->post('/scanner/schedules', [
            'name'       => 'Weekly main journal',
            'target_url' => 'http://ojs.test',
            'scan_type'  => 'external',
            'frequency'  => 'weekly',
            'time'       => '02:00',
            'weekday'    => 1,
            'is_active'  => '1',
        ]);

        $response->assertRedirect(route('scanner.schedules.index', absolute: false));

        $schedule = ScanSchedule::first();
        $this->assertNotNull($schedule);
        $this->assertSame('0 2 * * 1', $schedule->cron_expression);
        $this->assertTrue($schedule->is_active);
        $this->assertNotNull($schedule->next_run_at);
    }

    public function test_blank_password_on_update_keeps_existing_credential(): void
    {
        $user = User::factory()->create();
        $schedule = ScanSchedule::create([
            'user_id'         => $user->id,
            'name'            => 'Internal nightly',
            'target_url'      => 'http://ojs.test',
            'scan_type'       => 'internal',
            'admin_username'  => 'ojsadmin',
            'admin_password'  => 'secret123',
            'frequency'       => 'daily',
            'cron_expression' => '0 2 * * *',
            'timezone'        => 'UTC',
            'is_active'       => true,
            'next_run_at'     => now()->addDay(),
        ]);

        $this->actingAs($user)->put('/scanner/schedules/'.$schedule->id, [
            'name'           => 'Internal nightly',
            'target_url'     => 'http://ojs.test',
            'scan_type'      => 'internal',
            'admin_username' => 'ojsadmin',
            'admin_password' => '', // kosong = pertahankan
            'frequency'      => 'daily',
            'time'           => '03:00',
            'is_active'      => '1',
        ]);

        $schedule->refresh();
        $this->assertSame('secret123', $schedule->admin_password);
        $this->assertSame('0 3 * * *', $schedule->cron_expression);
    }

    public function test_dispatch_due_command_triggers_scan_for_due_schedule(): void
    {
        Http::fake([
            'http://scanner:5000/scan' => Http::response(['scan_id' => 987, 'status' => 'running'], 202),
        ]);

        $user = User::factory()->create();
        $schedule = ScanSchedule::create([
            'user_id'         => $user->id,
            'name'            => 'Due external',
            'target_url'      => 'http://ojs.test',
            'scan_type'       => 'external',
            'frequency'       => 'daily',
            'cron_expression' => '0 2 * * *',
            'timezone'        => 'UTC',
            'is_active'       => true,
            'next_run_at'     => now()->subMinute(),
        ]);

        $this->artisan('scans:dispatch-due')->assertSuccessful();

        $run = ScanRun::first();
        $this->assertNotNull($run);
        $this->assertSame('running', $run->status);
        $this->assertSame(987, $run->scanner_payload['scan_id']);

        $schedule->refresh();
        $this->assertSame($run->id, $schedule->last_scan_run_id);
        $this->assertTrue($schedule->next_run_at->isFuture());
    }

    public function test_inactive_or_future_schedules_are_not_dispatched(): void
    {
        Http::fake();

        $user = User::factory()->create();

        ScanSchedule::create([
            'user_id' => $user->id, 'name' => 'Paused', 'target_url' => 'http://ojs.test',
            'scan_type' => 'external', 'frequency' => 'daily', 'cron_expression' => '0 2 * * *',
            'timezone' => 'UTC', 'is_active' => false, 'next_run_at' => now()->subMinute(),
        ]);
        ScanSchedule::create([
            'user_id' => $user->id, 'name' => 'Future', 'target_url' => 'http://ojs.test',
            'scan_type' => 'external', 'frequency' => 'daily', 'cron_expression' => '0 2 * * *',
            'timezone' => 'UTC', 'is_active' => true, 'next_run_at' => now()->addHour(),
        ]);

        $this->artisan('scans:dispatch-due')->assertSuccessful();

        $this->assertSame(0, ScanRun::count());
        Http::assertNothingSent();
    }
}
