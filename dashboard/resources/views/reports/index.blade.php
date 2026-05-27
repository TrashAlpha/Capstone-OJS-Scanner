@extends('layouts.dashboard')

@section('page-title', 'Reports')

@section('content')
<div class="page-title">Reports</div>
<div class="page-sub">Laporan hasil analisis keamanan OJS</div>

<div class="table-wrap" style="margin-top:16px;">
  <table>
    <thead>
      <tr>
        <th>Target</th>
        <th>Type</th>
        <th>Total Findings</th>
        <th>Max CVSS</th>
        <th>Severity</th>
        <th>Scanned At</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      @forelse($scanRuns as $scanRun)
      @php $risk = strtolower($scanRun->summary_severity ?? 'informational'); @endphp
      <tr>
        <td class="mono">{{ $scanRun->target_url }}</td>
        <td><span class="badge {{ $scanRun->scan_type === 'external' ? 'type-ext' : 'type-int' }}">{{ strtoupper($scanRun->scan_type) }}</span></td>
        <td>{{ $scanRun->summary_total_findings }}</td>
        <td class="mono">{{ number_format($scanRun->summary_max_score, 1) }}</td>
        <td><span class="badge risk-{{ $risk }}">{{ strtoupper($risk) }}</span></td>
        <td>{{ $scanRun->scanned_at?->format('Y-m-d H:i:s') }}</td>
        <td><a href="{{ route('scanner.show', $scanRun) }}" class="link-action">View</a></td>
      </tr>
      @empty
      <tr>
        <td colspan="7" style="text-align:center; padding:40px; color:#484f58;">Belum ada laporan. Jalankan scan terlebih dahulu.</td>
      </tr>
      @endforelse
    </tbody>
  </table>
</div>
@endsection
