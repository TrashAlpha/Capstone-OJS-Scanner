@extends('layouts.dashboard')

@section('page-title', 'Scan Logs')

@section('content')
<div class="page-title">Scan Logs</div>
<div class="page-sub">Seluruh riwayat hasil scanning keamanan OJS</div>

{{-- FILTER --}}
<form method="GET" style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom:20px;">
  <input type="text" name="search" value="{{ request('search') }}"
    placeholder="Search target, finding..."
    style="flex:1; min-width:200px; background:#161b22; border:1px solid #30363d; color:#e6edf3; padding:7px 12px; border-radius:8px; font-size:12px;">

  <select name="risk" style="background:#161b22; border:1px solid #30363d; color:#e6edf3; padding:7px 12px; border-radius:8px; font-size:12px;">
        <option value="">All Risk Levels</option>
        <option value="critical" {{ request('risk')=='critical'?'selected':'' }}>Critical</option>
        <option value="high"     {{ request('risk')=='high'?'selected':'' }}>High</option>
        <option value="medium"   {{ request('risk')=='medium'?'selected':'' }}>Medium</option>
        <option value="low"      {{ request('risk')=='low'?'selected':'' }}>Low</option>
  </select>

  <select name="type" style="background:#161b22; border:1px solid #30363d; color:#e6edf3; padding:7px 12px; border-radius:8px; font-size:12px;">
        <option value="">All Types</option>
        <option value="external" {{ request('type')=='external'?'selected':'' }}>External</option>
        <option value="internal" {{ request('type')=='internal'?'selected':'' }}>Internal</option>
  </select>

  <button type="submit" style="background:#1f6feb22; border:1px solid #1f6feb44; color:#58a6ff; padding:7px 16px; border-radius:8px; font-size:12px; cursor:pointer;">
    Filter
  </button>
  <a href="{{ route('scanner.logs') }}" style="color:#8b949e; font-size:12px; display:flex; align-items:center;">Reset</a>
</form>

{{-- TABLE --}}
<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Target</th>
        <th>Type</th>
        <th>Category</th>
        <th>Finding</th>
        <th>CVSS</th>
        <th>Risk</th>
        <th>Scanned at</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      @forelse($logs ?? [] as $i => $log)
      @php $risk = strtolower($log['risk'] ?? 'low'); @endphp
      <tr>
        <td style="color:#484f58;">{{ $i + 1 }}</td>
        <td class="mono">{{ $log['target'] ?? '-' }}</td>
        <td><span class="badge {{ ($log['type']??'')=='external' ? 'type-ext' : 'type-int' }}">{{ strtoupper($log['type'] ?? '-') }}</span></td>
        <td>{{ $log['category'] ?? '-' }}</td>
        <td style="max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="{{ $log['finding']??'' }}">{{ $log['finding'] ?? '-' }}</td>
        <td style="font-family:monospace; font-size:11px; font-weight:600; color:{{ match($risk){ 'critical'=>'#f85149','high'=>'#f0883e','medium'=>'#58a6ff',default=>'#3fb950' } }}">{{ $log['cvss_score'] ?? '-' }}</td>
        <td><span class="badge risk-{{ $risk }}">{{ strtoupper($risk) }}</span></td>
        <td style="color:#8b949e; font-size:11px; white-space:nowrap;">{{ $log['scanned_at'] ?? '-' }}</td>
        <td><a href="#" class="link-action">Detail</a></td>
      </tr>
      @empty
      <tr>
        <td colspan="9" style="text-align:center; padding:40px; color:#484f58;">No results found.</td>
      </tr>
      @endforelse
    </tbody>
  </table>
</div>

{{-- PAGINATION (diisi backend nanti) --}}
{{-- @if(isset($logs) && method_exists($logs, 'links'))
<div style="margin-top:16px;">{{ $logs->links() }}</div>
@endif --}}
@endsection