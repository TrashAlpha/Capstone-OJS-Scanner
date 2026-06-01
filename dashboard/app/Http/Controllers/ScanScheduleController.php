<?php

namespace App\Http\Controllers;

use App\Models\ScanSchedule;
use App\Services\ScanRunner;
use App\Support\CronBuilder;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;
use Throwable;

class ScanScheduleController extends Controller
{
    public function index(): View
    {
        $schedules = ScanSchedule::where('user_id', auth()->id())
            ->latest()
            ->get();

        return view('scanner.schedules.index', compact('schedules'));
    }

    public function create(): View
    {
        return view('scanner.schedules.form', ['schedule' => new ScanSchedule()]);
    }

    public function store(Request $request, ScanRunner $runner): RedirectResponse
    {
        $data = $this->validateInput($request);

        $schedule = new ScanSchedule();
        $this->fillSchedule($schedule, $data, isUpdate: false);
        $schedule->user_id = auth()->id();
        $schedule->next_run_at = $schedule->computeNextRunAt();
        $schedule->save();

        return redirect()->route('scanner.schedules.index')
            ->with('status', "Jadwal '{$schedule->name}' berhasil dibuat.");
    }

    public function edit(ScanSchedule $schedule): View
    {
        $this->authorizeOwner($schedule);

        return view('scanner.schedules.form', compact('schedule'));
    }

    public function update(Request $request, ScanSchedule $schedule): RedirectResponse
    {
        $this->authorizeOwner($schedule);

        $data = $this->validateInput($request);
        $this->fillSchedule($schedule, $data, isUpdate: true);
        $schedule->next_run_at = $schedule->computeNextRunAt();
        $schedule->save();

        return redirect()->route('scanner.schedules.index')
            ->with('status', "Jadwal '{$schedule->name}' berhasil diperbarui.");
    }

    public function destroy(ScanSchedule $schedule): RedirectResponse
    {
        $this->authorizeOwner($schedule);
        $name = $schedule->name;
        $schedule->delete();

        return redirect()->route('scanner.schedules.index')
            ->with('status', "Jadwal '{$name}' dihapus.");
    }

    public function toggle(ScanSchedule $schedule): RedirectResponse
    {
        $this->authorizeOwner($schedule);
        $schedule->is_active = ! $schedule->is_active;
        if ($schedule->is_active) {
            $schedule->next_run_at = $schedule->computeNextRunAt();
        }
        $schedule->save();

        return redirect()->route('scanner.schedules.index')
            ->with('status', $schedule->is_active ? 'Jadwal diaktifkan.' : 'Jadwal dinonaktifkan.');
    }

    public function runNow(ScanSchedule $schedule, ScanRunner $runner): RedirectResponse
    {
        $this->authorizeOwner($schedule);

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
                'last_scan_run_id' => $run->id,
            ])->save();

            return redirect()->route('dashboard')
                ->with('status', "Scan dari jadwal '{$schedule->name}' dimulai. Hasil akan muncul otomatis.");
        } catch (Throwable $e) {
            return redirect()->route('scanner.schedules.index')
                ->withErrors(['schedule' => 'Gagal memulai scan: '.$e->getMessage()]);
        }
    }

    private function validateInput(Request $request): array
    {
        return $request->validate([
            'name'           => ['required', 'string', 'max:255'],
            'target_url'     => ['required', 'url'],
            'scan_type'      => ['required', 'in:external,internal,full'],
            'admin_username' => ['nullable', 'string', 'max:255', 'required_if:scan_type,internal,full'],
            'admin_password' => ['nullable', 'string', 'max:255'],
            'frequency'      => ['required', 'in:hourly,daily,weekly,monthly'],
            'time'           => ['nullable', 'date_format:H:i'],
            'weekday'        => ['nullable', 'integer', 'between:0,6'],
            'day_of_month'   => ['nullable', 'integer', 'between:1,28'],
            'is_active'      => ['nullable', 'boolean'],
        ]);
    }

    private function fillSchedule(ScanSchedule $schedule, array $data, bool $isUpdate): void
    {
        $schedule->name = $data['name'];
        $schedule->target_url = $data['target_url'];
        $schedule->scan_type = $data['scan_type'];
        $schedule->admin_username = $data['admin_username'] ?? null;

        // Password kosong saat update = pertahankan yang lama; saat create = null.
        if (! empty($data['admin_password'])) {
            $schedule->admin_password = $data['admin_password'];
        } elseif (! $isUpdate) {
            $schedule->admin_password = null;
        }

        $schedule->frequency = $data['frequency'];
        $schedule->cron_expression = CronBuilder::build(
            $data['frequency'],
            $data['time'] ?? null,
            isset($data['weekday']) ? (int) $data['weekday'] : null,
            isset($data['day_of_month']) ? (int) $data['day_of_month'] : null,
        );
        $schedule->timezone = config('app.timezone', 'UTC');
        $schedule->is_active = (bool) ($data['is_active'] ?? false);
    }

    private function authorizeOwner(ScanSchedule $schedule): void
    {
        abort_unless($schedule->user_id === auth()->id(), 403);
    }
}
