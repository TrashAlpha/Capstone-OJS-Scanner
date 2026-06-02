<?php

namespace App\Console\Commands;

use App\Models\ScanRun;
use App\Services\ScanRunner;
use Illuminate\Console\Command;
use Throwable;

class FinalizeRunningScansCommand extends Command
{
    protected $signature = 'scans:finalize {--timeout=15 : Menit sebelum scan yang menggantung ditandai failed}';

    protected $description = 'Finalisasi ScanRun yang masih running dengan membaca status dari scanner';

    public function handle(ScanRunner $runner): int
    {
        $timeoutMinutes = (int) $this->option('timeout');

        $running = ScanRun::where('status', 'running')->get();

        if ($running->isEmpty()) {
            $this->info('Tidak ada scan yang berjalan.');

            return self::SUCCESS;
        }

        foreach ($running as $run) {
            try {
                $status = $runner->finalize($run);

                if ($status === 'running' && $run->created_at && $run->created_at->lt(now()->subMinutes($timeoutMinutes))) {
                    $run->update(['status' => 'failed']);
                    $this->warn("scan_run #{$run->id} menggantung > {$timeoutMinutes} menit → ditandai failed.");

                    continue;
                }

                $this->info("scan_run #{$run->id} → {$status}.");
            } catch (Throwable $e) {
                $this->error("scan_run #{$run->id} gagal difinalisasi: {$e->getMessage()}");
            }
        }

        return self::SUCCESS;
    }
}
