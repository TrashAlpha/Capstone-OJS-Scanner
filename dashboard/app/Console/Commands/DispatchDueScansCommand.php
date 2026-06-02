<?php

namespace App\Console\Commands;

use App\Models\ScanSchedule;
use App\Services\ScanRunner;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Throwable;

class DispatchDueScansCommand extends Command
{
    protected $signature = 'scans:dispatch-due';

    protected $description = 'Trigger scan untuk semua jadwal aktif yang sudah jatuh tempo';

    public function handle(ScanRunner $runner): int
    {
        $due = ScanSchedule::where('is_active', true)
            ->whereNotNull('next_run_at')
            ->where('next_run_at', '<=', now())
            ->get();

        if ($due->isEmpty()) {
            $this->info('Tidak ada jadwal yang jatuh tempo.');

            return self::SUCCESS;
        }

        foreach ($due as $schedule) {
            try {
                $run = $runner->dispatch(
                    $schedule->target_url,
                    $schedule->scan_type,
                    $schedule->admin_username,
                    $schedule->admin_password,
                    $schedule->user_id,
                    $schedule,
                );

                $schedule->forceFill([
                    'last_run_at'      => now(),
                    'next_run_at'      => $schedule->computeNextRunAt(),
                    'last_scan_run_id' => $run->id,
                ])->save();

                $this->info("Jadwal #{$schedule->id} ('{$schedule->name}') dipicu → scan_run #{$run->id}.");
            } catch (Throwable $e) {
                Log::error('Gagal memicu jadwal scan', ['schedule_id' => $schedule->id, 'error' => $e->getMessage()]);
                $this->error("Jadwal #{$schedule->id} gagal: {$e->getMessage()}");

                // Tetap majukan next_run_at agar tidak terus-menerus mencoba di menit yang sama.
                $schedule->forceFill(['next_run_at' => $schedule->computeNextRunAt()])->save();
            }
        }

        return self::SUCCESS;
    }
}
