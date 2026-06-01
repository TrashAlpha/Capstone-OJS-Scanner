@extends('layouts.dashboard')

@section('page-title', 'Security Overview')

@section('content')
<div class="page-title">Security Overview</div>
<div class="page-sub">Ringkasan keamanan dan status scan aktif</div>

{{-- Flash message --}}
@if (session('status'))
<div style="margin-bottom:16px; background:#1f6feb15; border:1px solid #1f6feb44; color:#58a6ff; padding:10px 14px; border-radius:8px; font-size:12px;">
  {{ session('status') }}
</div>
@endif

{{-- STAT CARDS --}}
<div class="stat-grid">
  @php
  $cards = [
    ['label'=>'Total Scans', 'value'=>$stats['total']??0,  'color'=>'#8b949e', 'bg'=>'#8b949e18', 'icon'=>'search'],
    ['label'=>'High / Critical', 'value'=>$stats['high']??0, 'color'=>'#f85149', 'bg'=>'#f8514922', 'icon'=>'alert-octagon'],
    ['label'=>'Medium',      'value'=>$stats['medium']??0, 'color'=>'#f0883e', 'bg'=>'#f0883e22', 'icon'=>'alert-triangle'],
    ['label'=>'Low',         'value'=>$stats['low']??0,    'color'=>'#3fb950', 'bg'=>'#3fb95022', 'icon'=>'check-circle'],
  ];
  $icons = [
    'search' => '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    'alert-octagon' => '<polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
    'alert-triangle' => '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    'check-circle' => '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
  ];
  @endphp

  @foreach($cards as $card)
  <div class="stat-card">
    <div class="stat-card-top">
      <div class="stat-icon" style="background:{{ $card['bg'] }}; color:{{ $card['color'] }}">
        <svg viewBox="0 0 24 24">{!! $icons[$card['icon']] !!}</svg>
      </div>
    </div>
    <div class="stat-value" style="color:{{ $card['color'] }}">{{ $card['value'] }}</div>
    <div class="stat-label">{{ $card['label'] }}</div>
    <div class="stat-bar" style="background:{{ $card['color'] }}55"></div>
  </div>
  @endforeach
</div>

{{-- RUNNING SCANS --}}
<div class="section-header" style="margin-top:1.5rem;">
  <h2 style="display:flex; align-items:center; gap:8px;">
    @if($runningScans->isNotEmpty())
    <span style="width:8px; height:8px; background:#58a6ff; border-radius:50%; display:inline-block; animation:pulse-dot 1.5s ease-in-out infinite;"></span>
    @endif
    Running Scans
    @if($runningScans->isNotEmpty())
    <span style="font-size:11px; background:#58a6ff22; border:1px solid #58a6ff44; color:#58a6ff; padding:2px 8px; border-radius:12px; font-weight:600;">{{ $runningScans->count() }}</span>
    @endif
  </h2>
  <a href="{{ route('scanner.run') }}" style="font-size:12px; color:#58a6ff; text-decoration:none; background:#1f6feb22; border:1px solid #1f6feb44; padding:5px 12px; border-radius:8px;">+ New Scan</a>
</div>

@if($runningScans->isEmpty())
<div style="background:#161b22; border:1px solid #21262d; border-radius:10px; padding:24px; text-align:center; color:#484f58; font-size:12px; margin-bottom:24px;">
  Tidak ada scan yang sedang berjalan. <a href="{{ route('scanner.run') }}" style="color:#58a6ff;">Mulai scan baru</a>
</div>
@else
<div style="display:flex; flex-direction:column; gap:10px; margin-bottom:24px;">
  @foreach($runningScans as $scan)
  @php
    $typeClass = match($scan->scan_type) { 'external' => 'type-ext', 'internal' => 'type-int', 'full' => 'type-full', default => 'type-ext' };
    $startedAt = $scan->scanned_at?->toIso8601String() ?? now()->toIso8601String();
  @endphp
  <div id="running-card-{{ $scan->id }}"
       data-poll-url="{{ route('scanner.poll', $scan) }}"
       data-started-at="{{ $startedAt }}"
       style="background:#161b22; border:1px solid #1f6feb44; border-left:3px solid #58a6ff; border-radius:10px; padding:14px 18px; display:flex; align-items:center; gap:16px; flex-wrap:wrap;">

    {{-- Status indicator --}}
    <div style="display:flex; align-items:center; gap:7px; flex-shrink:0;">
      <span class="pulse-dot"></span>
      <span style="font-size:11px; font-weight:700; color:#58a6ff; letter-spacing:0.5px;">RUNNING</span>
    </div>

    {{-- Target URL --}}
    <div style="flex:1; min-width:0;">
      <div class="mono" style="font-size:12px; color:#e6edf3; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="{{ $scan->target_url }}">
        {{ $scan->target_url }}
      </div>
      <div style="font-size:10px; color:#8b949e; margin-top:2px;">
        Dimulai: {{ $scan->scanned_at?->format('Y-m-d H:i:s') ?? '-' }}
      </div>
    </div>

    {{-- Scan type --}}
    <span class="badge {{ $typeClass }}" style="flex-shrink:0;">{{ strtoupper($scan->scan_type) }}</span>

    {{-- Elapsed timer --}}
    <div style="flex-shrink:0; text-align:right;">
      <div style="font-size:11px; color:#8b949e;">Elapsed</div>
      <div class="elapsed-display" style="font-size:13px; font-weight:700; color:#e6edf3; font-family:monospace;">0s</div>
    </div>
  </div>
  @endforeach
</div>
@endif

{{-- COMPLETED SCANS --}}
<div class="section-header">
  <h2>Completed Scans</h2>
  <a href="{{ route('scanner.logs') }}" style="font-size:12px; color:#8b949e; text-decoration:none;">Lihat semua logs &rarr;</a>
</div>

@if($completedScans->isEmpty())
<div style="background:#161b22; border:1px solid #21262d; border-radius:10px; padding:24px; text-align:center; color:#484f58; font-size:12px;">
  Belum ada scan yang selesai.
</div>
@else
<div style="display:grid; grid-template-columns:repeat(auto-fill, minmax(320px, 1fr)); gap:12px;">
  @foreach($completedScans as $scan)
  @php
    $sev = strtolower($scan->summary_severity ?? 'informational');
    $sevColor = match(true) {
      in_array($sev, ['critical','kritis']) => '#f85149',
      in_array($sev, ['high','tinggi'])     => '#f0883e',
      in_array($sev, ['medium','sedang'])   => '#58a6ff',
      default                               => '#3fb950',
    };
    $typeClass = match($scan->scan_type) { 'external' => 'type-ext', 'internal' => 'type-int', 'full' => 'type-full', default => 'type-ext' };
    $duration = null;
    if ($scan->scanner_payload && isset($scan->scanner_payload['scan_duration_seconds'])) {
        $dur = $scan->scanner_payload['scan_duration_seconds'];
        $duration = $dur < 60 ? round($dur, 1).'s' : floor($dur/60).'m '.round($dur%60).'s';
    }
  @endphp
  <a href="{{ route('scanner.show', $scan) }}" style="text-decoration:none; display:block;">
    <div style="background:#161b22; border:1px solid #21262d; border-left:3px solid {{ $sevColor }}; border-radius:10px; padding:14px 16px; transition:border-color 0.15s; cursor:pointer;"
         onmouseover="this.style.borderColor='{{ $sevColor }}'" onmouseout="this.style.borderColor='#21262d'; this.style.borderLeftColor='{{ $sevColor }}'">

      {{-- Top row --}}
      <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px; gap:8px;">
        <div class="mono" style="font-size:12px; color:#e6edf3; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; flex:1;" title="{{ $scan->target_url }}">
          {{ $scan->target_url }}
        </div>
        <span class="badge {{ $typeClass }}" style="flex-shrink:0;">{{ strtoupper($scan->scan_type) }}</span>
      </div>

      {{-- Stats row --}}
      <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
        <div style="display:flex; align-items:center; gap:4px;">
          <span style="font-size:16px; font-weight:700; color:#e6edf3;">{{ $scan->summary_total_findings ?? 0 }}</span>
          <span style="font-size:10px; color:#8b949e;">findings</span>
        </div>
        <span style="font-size:11px; font-weight:700; color:{{ $sevColor }}; background:{{ $sevColor }}18; border:1px solid {{ $sevColor }}40; padding:2px 8px; border-radius:10px;">
          {{ strtoupper($scan->summary_severity ?? 'N/A') }}
        </span>
        @if($duration)
        <span style="font-size:10px; color:#484f58; margin-left:auto;">{{ $duration }}</span>
        @endif
      </div>

      {{-- Date --}}
      <div style="font-size:10px; color:#484f58; margin-top:8px;">
        {{ $scan->scanned_at?->format('Y-m-d H:i') ?? '-' }}
      </div>
    </div>
  </a>
  @endforeach
</div>
@endif

@endsection

@push('scripts')
<style>
@keyframes pulse-dot {
  0%, 100% { opacity: 1; transform: scale(1); }
  50%       { opacity: 0.4; transform: scale(0.85); }
}
.pulse-dot {
  width: 8px;
  height: 8px;
  background: #58a6ff;
  border-radius: 50%;
  display: inline-block;
  animation: pulse-dot 1.5s ease-in-out infinite;
}
</style>
<script>
(function () {
  // ── Elapsed timer untuk setiap running card ──────────────────
  function updateElapsed(card) {
    var startedAt = new Date(card.dataset.startedAt);
    var display = card.querySelector('.elapsed-display');
    if (!display || isNaN(startedAt)) return;
    var seconds = Math.floor((Date.now() - startedAt) / 1000);
    display.textContent = seconds < 60
      ? seconds + 's'
      : Math.floor(seconds / 60) + 'm ' + (seconds % 60) + 's';
  }

  var runningCards = document.querySelectorAll('[data-poll-url]');

  if (runningCards.length === 0) return;

  // Update elapsed setiap detik
  runningCards.forEach(updateElapsed);
  setInterval(function () { runningCards.forEach(updateElapsed); }, 1000);

  // ── Polling status setiap 5 detik ───────────────────────────
  var pollCount = 0;
  var maxPolls = 120; // berhenti setelah 10 menit (120 × 5s)

  function pollAll() {
    if (pollCount >= maxPolls) return;
    pollCount++;

    runningCards.forEach(function (card) {
      var url = card.dataset.pollUrl;
      if (!url || card.dataset.done) return;

      fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (data.status === 'completed') {
            card.dataset.done = '1';
            // Reload dashboard untuk tampilkan card di section Completed
            window.location.reload();
          } else if (data.status === 'failed') {
            card.dataset.done = '1';
            card.style.borderLeftColor = '#f85149';
            card.style.borderColor = '#f8514944';
            var statusEl = card.querySelector('span[style*="RUNNING"]') || card.querySelector('.pulse-dot');
            if (statusEl && statusEl.nextElementSibling) {
              statusEl.nextElementSibling.textContent = 'FAILED';
              statusEl.nextElementSibling.style.color = '#f85149';
            }
            var dot = card.querySelector('.pulse-dot');
            if (dot) { dot.style.background = '#f85149'; dot.style.animation = 'none'; }
            var elapsed = card.querySelector('.elapsed-display');
            if (elapsed) { elapsed.style.color = '#f85149'; }
          }
          // 'running' → tidak perlu update, timer sudah jalan
        })
        .catch(function () { /* network error, coba lagi di interval berikutnya */ });
    });
  }

  setInterval(pollAll, 5000);
})();
</script>
@endpush
