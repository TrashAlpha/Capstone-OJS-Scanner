@extends('layouts.dashboard')

@section('page-title', 'Scan Details')

@section('content')
<div class="page-title">Scan Details</div>
<div class="page-sub">Target: {{ $scanRun->target_url }} • {{ strtoupper($scanRun->scan_type) }} • {{ $scanRun->scanned_at?->format('Y-m-d H:i:s') }}</div>

@if (session('status'))
<div style="margin:16px 0; background:#3fb95015; border:1px solid #3fb95044; color:#7ee787; padding:10px 12px; border-radius:8px; font-size:12px;">
  {{ session('status') }}
</div>
@endif

<div class="stat-grid" style="margin-top:16px;">
  <div class="stat-card"><div class="stat-value">{{ $scanRun->summary_total_findings }}</div><div class="stat-label">Findings</div></div>
  <div class="stat-card"><div class="stat-value">{{ number_format($scanRun->summary_max_score, 1) }}</div><div class="stat-label">Max CVSS</div></div>
  <div class="stat-card"><div class="stat-value">{{ $scanRun->summary_severity }}</div><div class="stat-label">Overall Severity</div></div>
  <div class="stat-card"><div class="stat-value">{{ $scanRun->user?->name ?? 'System' }}</div><div class="stat-label">Executed By</div></div>
</div>

@if (!empty($scanRun->warnings))
<div style="margin:16px 0; background:#f0883e15; border:1px solid #f0883e44; color:#f2cc60; padding:10px 12px; border-radius:8px; font-size:12px;">
  {{ implode(' ', $scanRun->warnings) }}
</div>
@endif

<div class="table-wrap" style="margin-top:20px;">
  <table>
    <thead>
      <tr>
        <th>Finding</th>
        <th>Category</th>
        <th>CWE</th>
        <th>CVSS</th>
        <th>Risk</th>
        <th>Evidence</th>
      </tr>
    </thead>
    <tbody>
      @forelse($findings as $finding)
      @php $risk = strtolower($finding->risk ?? 'low'); @endphp
      <tr>
        <td>{{ $finding->finding }}</td>
        <td>{{ $finding->category ?? '-' }}</td>
        <td class="mono">{{ $finding->cwe_id ?? '-' }}</td>
        <td class="mono">{{ $finding->cvss_score }}</td>
        <td><span class="badge risk-{{ $risk }}">{{ strtoupper($risk) }}</span></td>
        <td style="max-width:340px; white-space:normal; line-height:1.5; color:#8b949e;">{{ $finding->evidence ?? '-' }}</td>
      </tr>
      @empty
      <tr>
        <td colspan="6" style="text-align:center; padding:32px; color:#484f58;">No findings recorded.</td>
      </tr>
      @endforelse
    </tbody>
  </table>
</div>
@endsection
