@extends('layouts.dashboard')

@section('page-title', 'Scheduled Scans')

@section('content')
<div style="display:flex; align-items:center; justify-content:space-between;">
  <div>
    <div class="page-title">Scheduled Scans</div>
    <div class="page-sub">Atur scan otomatis berulang untuk target OJS Anda</div>
  </div>
  <a href="{{ route('scanner.schedules.create') }}"
     style="background:#1f6feb; color:#fff; padding:9px 16px; border-radius:8px; font-size:13px; font-weight:600; text-decoration:none;">
    + New Schedule
  </a>
</div>

@if (session('status'))
<div style="margin:16px 0; background:#3fb95015; border:1px solid #3fb95044; color:#7ee787; padding:10px 12px; border-radius:8px; font-size:12px;">
  {{ session('status') }}
</div>
@endif

@if ($errors->any())
<div style="margin:16px 0; background:#f8514915; border:1px solid #f8514944; color:#fdaeb7; padding:10px 12px; border-radius:8px; font-size:12px;">
  {{ $errors->first() }}
</div>
@endif

<div class="table-wrap" style="margin-top:20px;">
  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>Target</th>
        <th>Type</th>
        <th>Frequency</th>
        <th>Next Run</th>
        <th>Last Run</th>
        <th>Status</th>
        <th style="text-align:right;">Actions</th>
      </tr>
    </thead>
    <tbody>
      @forelse($schedules as $schedule)
      <tr>
        <td>{{ $schedule->name }}</td>
        <td style="color:#8b949e;">{{ $schedule->target_url }}</td>
        <td><span class="badge">{{ strtoupper($schedule->scan_type) }}</span></td>
        <td style="text-transform:capitalize;">
          {{ $schedule->frequency }}
          <span class="mono" style="color:#484f58; font-size:11px;">({{ $schedule->cron_expression }})</span>
        </td>
        <td class="mono" style="color:#8b949e;">{{ $schedule->next_run_at?->format('Y-m-d H:i') ?? '-' }}</td>
        <td class="mono" style="color:#8b949e;">{{ $schedule->last_run_at?->format('Y-m-d H:i') ?? '-' }}</td>
        <td>
          @if($schedule->is_active)
            <span class="badge risk-low">ACTIVE</span>
          @else
            <span class="badge" style="color:#8b949e;">PAUSED</span>
          @endif
        </td>
        <td style="text-align:right; white-space:nowrap;">
          <form method="POST" action="{{ route('scanner.schedules.run', $schedule) }}" style="display:inline;">
            @csrf
            <button type="submit" title="Run now" style="background:none; border:none; color:#3fb950; cursor:pointer; font-size:12px; padding:4px;">Run</button>
          </form>
          <form method="POST" action="{{ route('scanner.schedules.toggle', $schedule) }}" style="display:inline;">
            @csrf
            <button type="submit" title="Toggle" style="background:none; border:none; color:#58a6ff; cursor:pointer; font-size:12px; padding:4px;">{{ $schedule->is_active ? 'Pause' : 'Resume' }}</button>
          </form>
          <a href="{{ route('scanner.schedules.edit', $schedule) }}" style="color:#8b949e; font-size:12px; padding:4px; text-decoration:none;">Edit</a>
          <form method="POST" action="{{ route('scanner.schedules.destroy', $schedule) }}" style="display:inline;" onsubmit="return confirm('Hapus jadwal ini?');">
            @csrf
            @method('DELETE')
            <button type="submit" title="Delete" style="background:none; border:none; color:#f85149; cursor:pointer; font-size:12px; padding:4px;">Delete</button>
          </form>
        </td>
      </tr>
      @empty
      <tr>
        <td colspan="8" style="text-align:center; padding:32px; color:#484f58;">
          Belum ada jadwal. Klik <strong>+ New Schedule</strong> untuk membuat scan otomatis.
        </td>
      </tr>
      @endforelse
    </tbody>
  </table>
</div>
@endsection
