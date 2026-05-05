@extends('layouts.dashboard')

@section('page-title', 'Security Overview')

@section('content')
<div class="page-title">Security Overview</div>
<div class="page-sub">Last scan: {{ $lastScan ?? 'No scans yet' }}</div>

{{-- STAT CARDS --}}
<div class="stat-grid">
  @php
  $cards = [
    ['label'=>'Total Scans', 'value'=>$stats['total']??0,  'color'=>'#8b949e', 'bg'=>'#8b949e18', 'icon'=>'search'],
    ['label'=>'High',        'value'=>$stats['high']??0,   'color'=>'#f85149', 'bg'=>'#f8514922', 'icon'=>'alert-octagon'],
    ['label'=>'Medium',      'value'=>$stats['medium']??0, 'color'=>'#f0883e', 'bg'=>'#f0883e22', 'icon'=>'alert-triangle'],
    ['label'=>'Low',         'value'=>$stats['low']??0,    'color'=>'#3fb950', 'bg'=>'#3fb95022', 'icon'=>'check-circle'],
  ];
  $icons = [
    'search' => '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    'alert-octagon' => '<polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
    'alert-triangle' => '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    'alert-circle' => '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
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

{{-- RECENT LOGS TABLE --}}
<div class="section-header">
  <h2>Recent scan results</h2>
  <a href="{{ route('scanner.logs') }}">View all logs &rarr;</a>
</div>
<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Target</th>
        <th>Type</th>
        <th>Category</th>
        <th>Finding</th>
        <th>CVSS</th>
        <th>Risk</th>
        <th>Scanned at</th>
      </tr>
    </thead>
    <tbody>
      @forelse($recentLogs ?? [] as $log)
      @php $risk = strtolower($log['risk'] ?? 'low'); @endphp
      <tr>
        <td class="mono">{{ $log['target'] ?? '-' }}</td>
        <td>
          <span class="badge {{ ($log['type']??'')=='external' ? 'type-ext' : 'type-int' }}">
            {{ strtoupper($log['type'] ?? '-') }}
          </span>
        </td>
        <td>{{ $log['category'] ?? '-' }}</td>
        <td style="max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
          {{ $log['finding'] ?? '-' }}
        </td>
        <td style="font-family:monospace; font-size:11px;">{{ $log['cvss_score'] ?? '-' }}</td>
        <td>
          <span class="badge risk-{{ $risk }}">{{ strtoupper($risk) }}</span>
        </td>
        <td style="color:#8b949e; font-size:11px;">{{ $log['scanned_at'] ?? '-' }}</td>
      </tr>
      @empty
      <tr>
        <td colspan="7" style="text-align:center; padding:32px; color:#484f58;">
          No scan data yet. <a href="{{ route('scanner.run') }}" style="color:#58a6ff;">Run a scan</a>
        </td>
      </tr>
      @endforelse
    </tbody>
  </table>
</div>
@endsection