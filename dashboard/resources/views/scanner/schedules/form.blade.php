@extends('layouts.dashboard')

@section('page-title', $schedule->exists ? 'Edit Schedule' : 'New Schedule')

@php
  $parts = preg_split('/\s+/', $schedule->cron_expression ?? '0 2 * * *');
  $cMin  = $parts[0] ?? '0';
  $cHour = $parts[1] ?? '2';
  $cDom  = $parts[2] ?? '*';
  $cDow  = $parts[4] ?? '*';
  $defaultTime = ($cHour === '*' ? '00' : str_pad($cHour, 2, '0', STR_PAD_LEFT)).':'.str_pad($cMin === '*' ? '0' : $cMin, 2, '0', STR_PAD_LEFT);

  $freqVal    = old('frequency', $schedule->frequency ?? 'daily');
  $typeVal    = old('scan_type', $schedule->scan_type ?? 'external');
  $timeVal    = old('time', $defaultTime);
  $weekdayVal = (int) old('weekday', $cDow !== '*' ? (int) $cDow : 1);
  $domVal     = (int) old('day_of_month', $cDom !== '*' ? (int) $cDom : 1);
  $activeVal  = old('is_active', $schedule->is_active ?? true);
@endphp

@section('content')
<div class="page-title">{{ $schedule->exists ? 'Edit Schedule' : 'New Schedule' }}</div>
<div class="page-sub">Konfigurasi scan otomatis berulang</div>

<div style="max-width:640px; margin-top:1rem;">
  <div style="background:#161b22; border:1px solid #21262d; border-radius:10px; padding:1.5rem;">

    @if ($errors->any())
      <div style="margin-bottom:1rem; background:#f8514915; border:1px solid #f8514944; color:#fdaeb7; padding:10px 12px; border-radius:8px; font-size:12px;">
        {{ $errors->first() }}
      </div>
    @endif

    <form method="POST" action="{{ $schedule->exists ? route('scanner.schedules.update', $schedule) : route('scanner.schedules.store') }}">
      @csrf
      @if($schedule->exists) @method('PUT') @endif

      {{-- NAME --}}
      <div style="margin-bottom:1.25rem;">
        <label style="display:block; font-size:11px; color:#8b949e; margin-bottom:6px; text-transform:uppercase; letter-spacing:0.5px;">Schedule Name <span style="color:#f85149;">*</span></label>
        <input type="text" name="name" value="{{ old('name', $schedule->name) }}" required placeholder="mis. Scan mingguan jurnal utama"
               style="width:100%; background:#0d1117; border:1px solid #30363d; color:#e6edf3; padding:8px 12px; border-radius:8px; font-size:13px; outline:none;">
      </div>

      {{-- TARGET URL --}}
      <div style="margin-bottom:1.25rem;">
        <label style="display:block; font-size:11px; color:#8b949e; margin-bottom:6px; text-transform:uppercase; letter-spacing:0.5px;">OJS URL <span style="color:#f85149;">*</span></label>
        <input type="url" name="target_url" value="{{ old('target_url', $schedule->target_url) }}" required placeholder="https://journal.example.ac.id"
               style="width:100%; background:#0d1117; border:1px solid #30363d; color:#e6edf3; padding:8px 12px; border-radius:8px; font-size:13px; outline:none;">
      </div>

      {{-- SCAN TYPE --}}
      <div style="margin-bottom:1.25rem;">
        <label style="display:block; font-size:11px; color:#8b949e; margin-bottom:8px; text-transform:uppercase; letter-spacing:0.5px;">Scan Type</label>
        <div style="display:flex; gap:8px;">
          @foreach(['external' => 'External', 'internal' => 'Internal', 'full' => 'Full Scan'] as $val => $label)
          <label style="flex:1; background:#0d1117; border:1px solid #30363d; border-radius:8px; padding:10px 14px; cursor:pointer; display:flex; align-items:center; gap:8px; font-size:12px;">
            <input type="radio" name="scan_type" value="{{ $val }}" {{ $typeVal === $val ? 'checked' : '' }} onchange="toggleCreds()"> {{ $label }}
          </label>
          @endforeach
        </div>
      </div>

      {{-- CREDENTIALS (internal/full) --}}
      <div id="credsBlock" style="margin-bottom:1.25rem; display:none;">
        <div style="border-top:1px solid #21262d; margin:0 0 1rem; position:relative;">
          <span style="position:absolute; top:-9px; left:0; background:#161b22; padding:0 8px 0 0; font-size:11px; color:#484f58;">Kredensial Admin OJS</span>
        </div>
        <div style="margin-bottom:1rem;">
          <label style="display:block; font-size:11px; color:#8b949e; margin-bottom:6px; text-transform:uppercase; letter-spacing:0.5px;">Username Admin</label>
          <input type="text" name="admin_username" value="{{ old('admin_username', $schedule->admin_username) }}" placeholder="ojsadmin"
                 style="width:100%; background:#0d1117; border:1px solid #30363d; color:#e6edf3; padding:8px 12px; border-radius:8px; font-size:13px; outline:none;">
        </div>
        <div>
          <label style="display:block; font-size:11px; color:#8b949e; margin-bottom:6px; text-transform:uppercase; letter-spacing:0.5px;">Password Admin</label>
          <input type="password" name="admin_password" autocomplete="new-password"
                 placeholder="{{ $schedule->exists && $schedule->admin_password ? '•••••••• (kosongkan = tidak diubah)' : '••••••••' }}"
                 style="width:100%; background:#0d1117; border:1px solid #30363d; color:#e6edf3; padding:8px 12px; border-radius:8px; font-size:13px; outline:none;">
          <div style="font-size:11px; color:#484f58; margin-top:4px;">Disimpan terenkripsi. Saat edit, kosongkan untuk mempertahankan password lama.</div>
        </div>
      </div>

      {{-- FREQUENCY --}}
      <div style="margin-bottom:1.25rem;">
        <label style="display:block; font-size:11px; color:#8b949e; margin-bottom:6px; text-transform:uppercase; letter-spacing:0.5px;">Frequency</label>
        <select name="frequency" id="frequency" onchange="toggleFreq()"
                style="width:100%; background:#0d1117; border:1px solid #30363d; color:#e6edf3; padding:8px 12px; border-radius:8px; font-size:13px; outline:none;">
          <option value="hourly"  {{ $freqVal === 'hourly'  ? 'selected' : '' }}>Setiap jam</option>
          <option value="daily"   {{ $freqVal === 'daily'   ? 'selected' : '' }}>Harian</option>
          <option value="weekly"  {{ $freqVal === 'weekly'  ? 'selected' : '' }}>Mingguan</option>
          <option value="monthly" {{ $freqVal === 'monthly' ? 'selected' : '' }}>Bulanan</option>
        </select>
      </div>

      {{-- TIME --}}
      <div id="timeBlock" style="margin-bottom:1.25rem;">
        <label style="display:block; font-size:11px; color:#8b949e; margin-bottom:6px; text-transform:uppercase; letter-spacing:0.5px;">Waktu (jam:menit)</label>
        <input type="time" name="time" value="{{ $timeVal }}"
               style="background:#0d1117; border:1px solid #30363d; color:#e6edf3; padding:8px 12px; border-radius:8px; font-size:13px; outline:none;">
        <div id="hourlyNote" style="font-size:11px; color:#484f58; margin-top:4px; display:none;">Untuk "setiap jam", hanya bagian <strong>menit</strong> yang dipakai.</div>
      </div>

      {{-- WEEKDAY (weekly) --}}
      <div id="weekdayBlock" style="margin-bottom:1.25rem; display:none;">
        <label style="display:block; font-size:11px; color:#8b949e; margin-bottom:6px; text-transform:uppercase; letter-spacing:0.5px;">Hari</label>
        <select name="weekday" style="width:100%; background:#0d1117; border:1px solid #30363d; color:#e6edf3; padding:8px 12px; border-radius:8px; font-size:13px; outline:none;">
          @foreach(['Minggu','Senin','Selasa','Rabu','Kamis','Jumat','Sabtu'] as $i => $day)
          <option value="{{ $i }}" {{ $weekdayVal === $i ? 'selected' : '' }}>{{ $day }}</option>
          @endforeach
        </select>
      </div>

      {{-- DAY OF MONTH (monthly) --}}
      <div id="domBlock" style="margin-bottom:1.25rem; display:none;">
        <label style="display:block; font-size:11px; color:#8b949e; margin-bottom:6px; text-transform:uppercase; letter-spacing:0.5px;">Tanggal (1–28)</label>
        <input type="number" name="day_of_month" min="1" max="28" value="{{ $domVal }}"
               style="width:120px; background:#0d1117; border:1px solid #30363d; color:#e6edf3; padding:8px 12px; border-radius:8px; font-size:13px; outline:none;">
      </div>

      {{-- ACTIVE --}}
      <div style="margin-bottom:1.5rem; display:flex; align-items:center; gap:8px;">
        <input type="hidden" name="is_active" value="0">
        <input type="checkbox" name="is_active" value="1" id="isActive" {{ $activeVal ? 'checked' : '' }}>
        <label for="isActive" style="font-size:13px; color:#c9d1d9;">Aktifkan jadwal ini</label>
      </div>

      <div style="display:flex; gap:10px;">
        <button type="submit" style="background:#1f6feb; border:none; color:#fff; padding:10px 18px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer;">
          {{ $schedule->exists ? 'Update Schedule' : 'Create Schedule' }}
        </button>
        <a href="{{ route('scanner.schedules.index') }}" style="background:#21262d; color:#c9d1d9; padding:10px 18px; border-radius:8px; font-size:13px; text-decoration:none;">Cancel</a>
      </div>
    </form>
  </div>
</div>
@endsection

@push('scripts')
<script>
function toggleCreds() {
  const type = document.querySelector('input[name="scan_type"]:checked').value;
  document.getElementById('credsBlock').style.display = (type === 'internal' || type === 'full') ? 'block' : 'none';
}
function toggleFreq() {
  const freq = document.getElementById('frequency').value;
  document.getElementById('weekdayBlock').style.display = (freq === 'weekly')  ? 'block' : 'none';
  document.getElementById('domBlock').style.display     = (freq === 'monthly') ? 'block' : 'none';
  document.getElementById('hourlyNote').style.display   = (freq === 'hourly')  ? 'block' : 'none';
}
toggleCreds();
toggleFreq();
</script>
@endpush
