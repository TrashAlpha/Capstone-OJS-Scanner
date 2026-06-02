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
  <div class="stat-card"><div class="stat-value"><span class="badge risk-{{ strtolower($scanRun->summary_severity ?? 'informational') }}" style="font-size:14px; padding:4px 12px;">{{ strtoupper($scanRun->summary_severity ?? 'N/A') }}</span></div><div class="stat-label">Overall Severity</div></div>
  <div class="stat-card"><div class="stat-value">{{ $scanRun->user?->name ?? 'System' }}</div><div class="stat-label">Executed By</div></div>
</div>

@if (!empty($scanRun->warnings))
<div style="margin:16px 0; background:#f0883e15; border:1px solid #f0883e44; color:#f2cc60; padding:10px 12px; border-radius:8px; font-size:12px;">
  {{ implode(' ', $scanRun->warnings) }}
</div>
@endif

{{-- LLM Analysis --}}
@php
  $sp = is_array($scanRun->scanner_payload) ? $scanRun->scanner_payload : [];
  $isFull = ($scanRun->scan_type === 'full');
  $llmSections = [];
  if (!empty($sp['llm_analysis'])) {
      $llmSections[] = ['label' => $isFull ? 'Analisis External (Nuclei)' : 'Hasil Analisis AI', 'data' => $sp['llm_analysis']];
  }
  if ($isFull && !empty($sp['internal']['llm_analysis'])) {
      $llmSections[] = ['label' => 'Analisis Internal (Authenticated)', 'data' => $sp['internal']['llm_analysis']];
  }
@endphp

@foreach($llmSections as $llmSection)
@php
  $llmData  = $llmSection['data'];
  $llmLabel = $llmSection['label'];
  $summaryRaw = $llmData['summary'] ?? '';
  if (str_starts_with(ltrim($summaryRaw), '{')) {
      $reparsed = json_decode($summaryRaw, true);
      if (is_array($reparsed)) { $llmData = array_merge($llmData, $reparsed); }
  }
  $llmRiskRaw = $llmData['risk_assessment'] ?? '';
  $llmRiskKey = '-';
  foreach (['KRITIS','CRITICAL','TINGGI','HIGH','SEDANG','MEDIUM','RENDAH','LOW'] as $_k) {
    if (str_contains(strtoupper((string)$llmRiskRaw), $_k)) { $llmRiskKey = $_k; break; }
  }
  $llmRiskColor = match(true) {
    in_array($llmRiskKey, ['KRITIS','CRITICAL']) => '#f85149',
    in_array($llmRiskKey, ['TINGGI','HIGH'])     => '#f0883e',
    in_array($llmRiskKey, ['SEDANG','MEDIUM'])   => '#58a6ff',
    in_array($llmRiskKey, ['RENDAH','LOW'])      => '#3fb950',
    default                                      => '#8b949e',
  };
  $rawResp = $llmData['raw_response'] ?? '';
  $isManualAnalysis = !empty($llmData['llm_failed'])
      || str_contains($rawResp, 'Fallback')
      || str_contains($rawResp, 'LLM tidak tersedia')
      || str_contains($rawResp, 'LLM gagal');
@endphp
@if(!empty($llmData['summary']))
<div style="border:1px solid #21262d; border-radius:10px; overflow:hidden; margin-bottom:16px; margin-top:20px;">

  {{-- Header --}}
  <div style="background:#161b22; padding:10px 16px; display:flex; align-items:center; justify-content:space-between; border-bottom:1px solid #21262d;">
    <span style="font-size:11px; font-weight:700; color:#58a6ff; text-transform:uppercase; letter-spacing:0.6px;">{{ $llmLabel }}</span>
    @if($llmRiskKey !== '-')
    <span style="font-size:11px; font-weight:800; color:{{ $llmRiskColor }}; background:{{ $llmRiskColor }}18; border:1px solid {{ $llmRiskColor }}50; padding:3px 12px; border-radius:20px; letter-spacing:0.5px;">
      {{ $llmRiskKey }}
    </span>
    @endif
  </div>

  {{-- LLM gagal banner --}}
  @if($isManualAnalysis)
  <div style="background:#f0883e12; border-bottom:1px solid #f0883e30; padding:8px 16px; display:flex; align-items:center; gap:8px;">
    <span style="font-size:14px;">&#9888;</span>
    <span style="font-size:11px; color:#f0883e;">Analisis AI (Gemini) gagal setelah 3 percobaan &mdash; hasil di bawah merupakan analisis manual berdasarkan data temuan.</span>
  </div>
  @endif

  <div style="padding:16px; background:#0d1117;">

    {{-- Penilaian Risiko --}}
    @if($llmRiskRaw)
    <div style="background:{{ $llmRiskColor }}0e; border:1px solid {{ $llmRiskColor }}30; border-left:3px solid {{ $llmRiskColor }}; border-radius:0 7px 7px 0; padding:10px 14px; margin-bottom:16px;">
      <div style="font-size:10px; font-weight:700; color:{{ $llmRiskColor }}; text-transform:uppercase; letter-spacing:0.6px; margin-bottom:6px;">Penilaian Risiko Keseluruhan</div>
      <div class="md-render" data-md="{{ e($llmRiskRaw) }}" style="font-size:12px; color:#c9d1d9;"></div>
    </div>
    @endif

    {{-- Ringkasan --}}
    <div style="margin-bottom:16px;">
      <div style="font-size:10px; font-weight:700; color:#8b949e; text-transform:uppercase; letter-spacing:0.6px; margin-bottom:10px; padding-bottom:6px; border-bottom:1px solid #21262d;">Ringkasan</div>
      <div class="md-render" data-md="{{ e($llmData['summary']) }}" style="font-size:13px; color:#c9d1d9; line-height:1.75;"></div>
    </div>

    {{-- Rekomendasi --}}
    @if(!empty($llmData['recommendations']))
    <div>
      <div style="font-size:10px; font-weight:700; color:#8b949e; text-transform:uppercase; letter-spacing:0.6px; margin-bottom:10px; padding-bottom:6px; border-bottom:1px solid #21262d;">Rekomendasi</div>
      @foreach($llmData['recommendations'] as $i => $rec)
      <div style="display:flex; gap:10px; align-items:flex-start; margin-bottom:8px; font-size:12px; color:#c9d1d9; line-height:1.5;">
        <span style="flex-shrink:0; width:20px; height:20px; background:#1f6feb22; border:1px solid #1f6feb44; color:#58a6ff; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:10px; font-weight:700;">{{ $i+1 }}</span>
        <span>{{ $rec }}</span>
      </div>
      @endforeach
    </div>
    @endif

  </div>
</div>
@endif
@endforeach

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

@push('scripts')
<script>
document.querySelectorAll('.md-render').forEach(function (el) {
  var text = el.dataset.md || '';
  // Bold (**text**)
  text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  // Italic (*text*)
  text = text.replace(/\*(.+?)\*/g, '<em>$1</em>');
  // Inline code (`code`)
  text = text.replace(/`([^`]+)`/g, '<code style="background:#161b22;padding:1px 5px;border-radius:4px;font-size:0.9em;">$1</code>');
  // Newlines
  text = text.replace(/\n/g, '<br>');
  el.innerHTML = text;
});
</script>
@endpush
