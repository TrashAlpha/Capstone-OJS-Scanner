@extends('layouts.dashboard')

@section('page-title', 'Scan Logs')

@section('content')
<div class="page-title">Scan Logs</div>
<div class="page-sub">Riwayat scan dari scanner service</div>

{{-- FILTER --}}
<form method="GET" style="display:flex; gap:10px; flex-wrap:wrap; margin:16px 0 20px;">
  <input type="text" name="search" value="{{ request('search') }}"
    placeholder="Cari target URL..."
    style="flex:1; min-width:200px; background:#161b22; border:1px solid #30363d; color:#e6edf3; padding:7px 12px; border-radius:8px; font-size:12px; outline:none;">

  <select name="type" style="background:#161b22; border:1px solid #30363d; color:#e6edf3; padding:7px 12px; border-radius:8px; font-size:12px;">
    <option value="">All Types</option>
    <option value="full"     {{ request('type')=='full'?'selected':'' }}>Full</option>
    <option value="external" {{ request('type')=='external'?'selected':'' }}>External</option>
    <option value="internal" {{ request('type')=='internal'?'selected':'' }}>Internal</option>
  </select>

  <select name="status" style="background:#161b22; border:1px solid #30363d; color:#e6edf3; padding:7px 12px; border-radius:8px; font-size:12px;">
    <option value="">All Status</option>
    <option value="completed" {{ request('status')=='completed'?'selected':'' }}>Completed</option>
    <option value="running"   {{ request('status')=='running'?'selected':'' }}>Running</option>
    <option value="failed"    {{ request('status')=='failed'?'selected':'' }}>Failed</option>
  </select>

  <button type="submit" style="background:#1f6feb22; border:1px solid #1f6feb44; color:#58a6ff; padding:7px 16px; border-radius:8px; font-size:12px; cursor:pointer;">Filter</button>
  <a href="{{ route('scanner.logs') }}" style="color:#8b949e; font-size:12px; display:flex; align-items:center; text-decoration:none;">Reset</a>
</form>

{{-- TABLE --}}
<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Target URL</th>
        <th>Type</th>
        <th>Status</th>
        <th>Findings</th>
        <th>Risk</th>
        <th>Duration</th>
        <th>Scanned At</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      @forelse($logs as $i => $log)
      @php
        $status = $log->status ?? 'unknown';
        $risk   = strtoupper($log->risk_assessment ?? '-');
        $statusColor = match($status) {
          'completed' => '#3fb950',
          'running'   => '#58a6ff',
          'failed'    => '#f85149',
          default     => '#8b949e',
        };
        $riskColor = match(strtolower($risk)) {
          'critical','kritis' => '#f85149',
          'high','tinggi'     => '#f0883e',
          'medium','sedang'   => '#58a6ff',
          default             => '#3fb950',
        };
        $duration = $log->scan_duration ? round($log->scan_duration, 1).'s' : '-';
      @endphp
      <tr>
        <td style="color:#484f58;">{{ $i + 1 }}</td>
        <td class="mono" style="max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="{{ $log->target_url }}">{{ $log->target_url }}</td>
        <td><span class="badge {{ match($log->scan_type) { 'external' => 'type-ext', 'internal' => 'type-int', 'full' => 'type-full', default => 'type-ext' } }}">{{ strtoupper($log->scan_type ?? '-') }}</span></td>
        <td><span style="font-size:11px; font-weight:600; color:{{ $statusColor }};">{{ strtoupper($status) }}</span></td>
        <td>
          @if($log->total_findings > 0)
          <span style="font-size:11px; color:#e6edf3;">{{ $log->total_findings }}</span>
          <span style="font-size:10px; color:#484f58; margin-left:4px;">
            @if($log->critical_count) <span style="color:#f85149;">{{ $log->critical_count }}C</span> @endif
            @if($log->high_count) <span style="color:#f0883e;">{{ $log->high_count }}H</span> @endif
            @if($log->medium_count) <span style="color:#58a6ff;">{{ $log->medium_count }}M</span> @endif
            @if($log->low_count) <span style="color:#3fb950;">{{ $log->low_count }}L</span> @endif
          </span>
          @else
          <span style="color:#484f58; font-size:11px;">0</span>
          @endif
        </td>
        <td style="font-size:11px; font-weight:600; color:{{ $riskColor }};">{{ $risk }}</td>
        <td style="font-size:11px; color:#8b949e;">{{ $duration }}</td>
        <td style="font-size:11px; color:#8b949e; white-space:nowrap;">{{ optional($log->created_at)->format('Y-m-d H:i') ?? '-' }}</td>
        <td>
          @if($log->result_json)
          <button onclick="openModal({{ $log->id }})"
            style="background:#1f6feb22; border:1px solid #1f6feb44; color:#58a6ff; padding:4px 10px; border-radius:6px; font-size:11px; cursor:pointer;">
            Detail
          </button>
          @elseif($status === 'failed')
          <span style="font-size:11px; color:#f85149;" title="{{ $log->error_message }}">Error</span>
          @else
          <span style="font-size:11px; color:#484f58;">-</span>
          @endif
        </td>
      </tr>
      @empty
      <tr>
        <td colspan="9" style="text-align:center; padding:40px; color:#484f58;">Belum ada scan log.</td>
      </tr>
      @endforelse
    </tbody>
  </table>
</div>

{{-- MODALS --}}
@foreach($logs as $log)
@if($log->result_json)
@php $r = $log->result_json; @endphp
<div id="modal-{{ $log->id }}" style="display:none; position:fixed; inset:0; z-index:1000; background:#00000088; overflow-y:auto; padding:24px 16px;">
  <div style="max-width:860px; margin:0 auto; background:#0d1117; border:1px solid #30363d; border-radius:12px; padding:24px; position:relative;">

    {{-- Header --}}
    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:20px;">
      <div>
        <div style="font-size:14px; font-weight:600; color:#e6edf3;">Scan Detail</div>
        <div style="font-size:11px; color:#8b949e; margin-top:2px;">{{ $log->target_url }} &mdash; {{ optional($log->created_at)->format('Y-m-d H:i:s') }}</div>
      </div>
      <button onclick="closeModal({{ $log->id }})" style="background:none; border:none; color:#8b949e; font-size:18px; cursor:pointer; line-height:1;">&times;</button>
    </div>

    {{-- Summary Cards --}}
    <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-bottom:20px;">
      @php
        $fc = $r['summary']['findings_count'] ?? [];
        $totalF = $r['summary']['total_findings'] ?? $log->total_findings ?? 0;
        $dur = $r['scan_duration_seconds'] ?? $log->scan_duration ?? null;
        // Ekstrak keyword risiko saja dari teks panjang LLM
        $riskRaw = $r['llm_analysis']['risk_assessment'] ?? $r['risk_engine']['summary']['overall_severity'] ?? $log->risk_assessment ?? '';
        $riskKeyword = '-';
        foreach (['KRITIS','CRITICAL','TINGGI','HIGH','SEDANG','MEDIUM','RENDAH','LOW'] as $_rk) {
          if (str_contains(strtoupper((string)$riskRaw), $_rk)) { $riskKeyword = $_rk; break; }
        }
        $riskCardColor = match(true) {
          in_array($riskKeyword, ['KRITIS','CRITICAL']) => '#f85149',
          in_array($riskKeyword, ['TINGGI','HIGH'])     => '#f0883e',
          in_array($riskKeyword, ['SEDANG','MEDIUM'])   => '#58a6ff',
          in_array($riskKeyword, ['RENDAH','LOW'])      => '#3fb950',
          default                                       => '#8b949e',
        };
      @endphp
      <div style="background:#161b22; border:1px solid #21262d; border-radius:8px; padding:12px; text-align:center;">
        <div style="font-size:20px; font-weight:700; color:#e6edf3;">{{ $totalF }}</div>
        <div style="font-size:10px; color:#8b949e; margin-top:2px;">Total Findings</div>
      </div>
      <div style="background:#161b22; border:1px solid #21262d; border-radius:8px; padding:12px; text-align:center;">
        <div style="font-size:15px; font-weight:800; color:{{ $riskCardColor }}; letter-spacing:0.5px;">{{ $riskKeyword }}</div>
        <div style="font-size:10px; color:#8b949e; margin-top:2px;">Risk Level</div>
      </div>
      <div style="background:#161b22; border:1px solid #21262d; border-radius:8px; padding:12px; text-align:center;">
        <div style="font-size:13px; font-weight:700; color:#e6edf3;">{{ strtoupper($log->scan_type ?? '-') }}</div>
        <div style="font-size:10px; color:#8b949e; margin-top:2px;">Scan Type</div>
      </div>
      <div style="background:#161b22; border:1px solid #21262d; border-radius:8px; padding:12px; text-align:center;">
        <div style="font-size:13px; font-weight:700; color:#e6edf3;">{{ $dur ? round($dur, 1).'s' : '-' }}</div>
        <div style="font-size:10px; color:#8b949e; margin-top:2px;">Duration</div>
      </div>
    </div>

    {{-- Severity Breakdown --}}
    @if(!empty($fc))
    <div style="display:flex; gap:8px; margin-bottom:20px; flex-wrap:wrap;">
      @foreach(['critical'=>'#f85149','high'=>'#f0883e','medium'=>'#58a6ff','low'=>'#3fb950','info'=>'#8b949e'] as $sev => $col)
      @if(($fc[$sev] ?? 0) > 0)
      <span style="background:{{ $col }}22; border:1px solid {{ $col }}44; color:{{ $col }}; padding:3px 10px; border-radius:20px; font-size:11px; font-weight:600;">
        {{ $fc[$sev] }} {{ strtoupper($sev) }}
      </span>
      @endif
      @endforeach
    </div>
    @endif

    {{-- LLM Analysis --}}
    @php
      /**
       * Kumpulkan sumber LLM analysis berdasarkan scan_type:
       * - full: external ($r['llm_analysis']) + internal ($r['internal']['llm_analysis'])
       * - external / external_nuclei: hanya $r['llm_analysis']
       * - internal: hanya $r['llm_analysis']
       */
      $llmSections = [];
      $isFull = ($log->scan_type === 'full');

      if (!empty($r['llm_analysis'])) {
          $llmSections[] = [
              'label' => $isFull ? 'Analisis External (Nuclei)' : 'Hasil Analisis',
              'data'  => $r['llm_analysis'],
          ];
      }
      if ($isFull && !empty($r['internal']['llm_analysis'])) {
          $llmSections[] = [
              'label' => 'Analisis Internal (Authenticated)',
              'data'  => $r['internal']['llm_analysis'],
          ];
      }
    @endphp

    @foreach($llmSections as $llmSection)
    @php
      $llmData = $llmSection['data'];
      $llmLabel = $llmSection['label'];
      // Jika summary menyimpan raw JSON (LLM parsing gagal), coba parse ulang
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
    <div style="border:1px solid #21262d; border-radius:10px; overflow:hidden; margin-bottom:16px;">

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
        <div style="margin-bottom:16px;">
          <div style="font-size:10px; font-weight:700; color:#8b949e; text-transform:uppercase; letter-spacing:0.6px; margin-bottom:10px; padding-bottom:6px; border-bottom:1px solid #21262d;">Rekomendasi</div>
          @foreach($llmData['recommendations'] as $i => $rec)
          <div style="display:flex; gap:10px; align-items:flex-start; margin-bottom:9px;">
            <span style="flex-shrink:0; width:20px; height:20px; background:#1f6feb20; border:1px solid #1f6feb50; border-radius:50%; display:inline-flex; align-items:center; justify-content:center; font-size:10px; font-weight:700; color:#58a6ff; margin-top:2px;">{{ $i + 1 }}</span>
            <div class="md-render" data-md="{{ e($rec) }}" style="font-size:12px; color:#c9d1d9; line-height:1.65; flex:1;"></div>
          </div>
          @endforeach
        </div>
        @endif

        {{-- Analisis Per Temuan --}}
        @if(!empty($llmData['finding_analysis']))
        <div>
          <div style="font-size:10px; font-weight:700; color:#8b949e; text-transform:uppercase; letter-spacing:0.6px; margin-bottom:10px; padding-bottom:6px; border-bottom:1px solid #21262d;">Analisis Per Temuan</div>
          @foreach($llmData['finding_analysis'] as $fa)
          @php
            $faRisk  = strtoupper($fa['risk_level'] ?? '');
            $faColor = match(true) {
              in_array($faRisk, ['KRITIS','CRITICAL']) => '#f85149',
              in_array($faRisk, ['TINGGI','HIGH'])     => '#f0883e',
              in_array($faRisk, ['SEDANG','MEDIUM'])   => '#58a6ff',
              default                                  => '#3fb950',
            };
            $faIdentifier = $fa['template_id'] ?? $fa['title'] ?? '-';
          @endphp
          <div style="border:1px solid #21262d; border-left:3px solid {{ $faColor }}; border-radius:0 7px 7px 0; padding:10px 14px; margin-bottom:8px; background:#161b2288;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:7px;">
              <code style="font-size:11px; color:#e6edf3; background:#21262d; padding:2px 7px; border-radius:4px;">{{ $faIdentifier }}</code>
              @if($faRisk)
              <span style="font-size:10px; font-weight:700; color:{{ $faColor }}; background:{{ $faColor }}20; padding:2px 9px; border-radius:4px;">{{ $faRisk }}</span>
              @endif
            </div>
            @if(!empty($fa['impact']))
            <div style="font-size:11px; color:#8b949e; margin-bottom:5px; display:flex; gap:5px; align-items:flex-start;">
              <span style="color:#f0883e; font-weight:600; flex-shrink:0;">Dampak:</span>
              <span>{{ $fa['impact'] }}</span>
            </div>
            @endif
            @if(!empty($fa['remediation']))
            <div style="font-size:11px; color:#8b949e; display:flex; gap:5px; align-items:flex-start;">
              <span style="color:#3fb950; font-weight:600; flex-shrink:0;">Perbaikan:</span>
              <span>{{ $fa['remediation'] }}</span>
            </div>
            @endif
          </div>
          @endforeach
        </div>
        @endif

      </div>
    </div>
    @endif
    @endforeach

    {{-- Nuclei Findings --}}
    @if(!empty($r['nuclei_results']))
    <div style="margin-bottom:16px;">
      <div style="font-size:11px; font-weight:600; color:#e6edf3; margin-bottom:10px; text-transform:uppercase; letter-spacing:0.5px;">Nuclei Findings ({{ count($r['nuclei_results']) }})</div>
      @foreach($r['nuclei_results'] as $finding)
      @php
        $sev = strtolower($finding['severity'] ?? 'info');
        $sevColor = match($sev) { 'critical'=>'#f85149','high'=>'#f0883e','medium'=>'#58a6ff','low'=>'#3fb950', default=>'#8b949e' };
      @endphp
      <div style="background:#161b22; border:1px solid #21262d; border-left:3px solid {{ $sevColor }}; border-radius:6px; padding:12px; margin-bottom:8px;">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:4px;">
          <div style="font-size:12px; font-weight:600; color:#e6edf3;">{{ $finding['template_name'] ?? $finding['template_id'] ?? '-' }}</div>
          <div style="display:flex; gap:6px; align-items:center; flex-shrink:0; margin-left:8px;">
            @if(!empty($finding['cvss_score']))
            <span style="font-size:10px; font-family:monospace; color:{{ $sevColor }}; font-weight:700;">CVSS {{ $finding['cvss_score'] }}</span>
            @endif
            <span style="font-size:10px; font-weight:700; color:{{ $sevColor }}; background:{{ $sevColor }}22; padding:2px 7px; border-radius:4px;">{{ strtoupper($sev) }}</span>
          </div>
        </div>
        @if(!empty($finding['description']))
        <div style="font-size:11px; color:#8b949e; margin-bottom:6px; line-height:1.5;">{{ $finding['description'] }}</div>
        @endif
        <div style="display:flex; gap:16px; flex-wrap:wrap;">
          @if(!empty($finding['matched_at']))
          <div style="font-size:10px; color:#484f58;"><span style="color:#58a6ff;">Matched:</span> {{ $finding['matched_at'] }}</div>
          @endif
          @if(!empty($finding['cwe_id']))
          <div style="font-size:10px; color:#484f58;"><span style="color:#58a6ff;">CWE:</span> {{ $finding['cwe_id'] }}</div>
          @endif
          @if(!empty($finding['cve_id']))
          <div style="font-size:10px; color:#484f58;"><span style="color:#f0883e;">CVE:</span> {{ $finding['cve_id'] }}</div>
          @endif
        </div>
        @if(!empty($finding['extracted_results']) && count($finding['extracted_results']) > 0)
        <div style="margin-top:6px; background:#0d1117; border-radius:4px; padding:6px 8px; font-size:10px; font-family:monospace; color:#7ee787; word-break:break-all;">{{ implode(', ', $finding['extracted_results']) }}</div>
        @endif
        @if(!empty($finding['impact']))
        <div style="margin-top:6px; font-size:10px; color:#484f58;"><span style="color:#f0883e;">Impact:</span> {{ $finding['impact'] }}</div>
        @endif
        @if(!empty($finding['remediation']))
        <div style="margin-top:4px; font-size:10px; color:#484f58;"><span style="color:#3fb950;">Fix:</span> {{ $finding['remediation'] }}</div>
        @endif
      </div>
      @endforeach
    </div>
    @endif

    {{-- Internal Module Findings --}}
    @if(!empty($r['module_results']))
    <div style="margin-bottom:16px;">
      <div style="font-size:11px; font-weight:600; color:#e6edf3; margin-bottom:10px; text-transform:uppercase; letter-spacing:0.5px;">Internal Findings</div>
      @foreach($r['module_results'] as $module)
      @if(!empty($module['findings']))
      <div style="margin-bottom:12px;">
        <div style="font-size:10px; color:#8b949e; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:6px;">{{ $module['module'] ?? 'Module' }}</div>
        @foreach($module['findings'] as $finding)
        @php
          $sev = strtolower($finding['severity'] ?? 'info');
          $sevColor = match($sev) { 'critical'=>'#f85149','high'=>'#f0883e','medium'=>'#58a6ff','low'=>'#3fb950', default=>'#8b949e' };
        @endphp
        <div style="background:#161b22; border:1px solid #21262d; border-left:3px solid {{ $sevColor }}; border-radius:6px; padding:12px; margin-bottom:6px;">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:4px;">
            <div style="font-size:12px; font-weight:600; color:#e6edf3;">{{ $finding['title'] ?? '-' }}</div>
            <span style="font-size:10px; font-weight:700; color:{{ $sevColor }}; background:{{ $sevColor }}22; padding:2px 7px; border-radius:4px; flex-shrink:0; margin-left:8px;">{{ strtoupper($sev) }}</span>
          </div>
          @if(!empty($finding['description']))
          <div style="font-size:11px; color:#8b949e; margin-bottom:6px; line-height:1.5;">{{ $finding['description'] }}</div>
          @endif
          @if(!empty($finding['evidence']))
          <div style="background:#0d1117; border-radius:4px; padding:6px 8px; font-size:10px; font-family:monospace; color:#7ee787; word-break:break-all; margin-bottom:6px;">{{ $finding['evidence'] }}</div>
          @endif
          @if(!empty($finding['remediation']))
          <div style="font-size:10px; color:#484f58;"><span style="color:#3fb950;">Fix:</span> {{ $finding['remediation'] }}</div>
          @endif
          @if(!empty($finding['cve']))
          <div style="font-size:10px; color:#484f58; margin-top:2px;"><span style="color:#58a6ff;">CWE/CVE:</span> {{ $finding['cve'] }}</div>
          @endif
        </div>
        @endforeach
      </div>
      @endif
      @endforeach
    </div>
    @endif

    {{-- No findings --}}
    @if(empty($r['nuclei_results']) && empty($r['module_results']))
    <div style="text-align:center; padding:24px; color:#484f58; font-size:12px;">Tidak ada findings yang tercatat.</div>
    @endif

    {{-- Raw JSON toggle --}}
    <div style="margin-top:16px; border-top:1px solid #21262d; padding-top:12px;">
      <button onclick="toggleRaw({{ $log->id }})" style="background:none; border:none; color:#8b949e; font-size:11px; cursor:pointer; padding:0;">
        &#x25B6; Lihat Raw JSON
      </button>
      <pre id="raw-{{ $log->id }}" style="display:none; margin-top:10px; background:#0d1117; border:1px solid #21262d; border-radius:6px; padding:14px; font-size:10px; color:#8b949e; overflow-x:auto; white-space:pre-wrap; word-break:break-all; max-height:400px; overflow-y:auto;">{{ json_encode($r, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) }}</pre>
    </div>

  </div>
</div>
@endif
@endforeach

@endsection

@push('scripts')
<script src="https://cdn.jsdelivr.net/npm/marked@9/marked.min.js"></script>
<style>
/* Markdown render styles — dark theme */
.md-render p        { margin: 0 0 8px 0; }
.md-render p:last-child { margin-bottom: 0; }
.md-render strong   { color: #e6edf3; font-weight: 700; }
.md-render em       { color: #c9d1d9; font-style: italic; }
.md-render ul, .md-render ol { margin: 6px 0 8px 16px; padding: 0; }
.md-render li       { margin-bottom: 4px; color: #c9d1d9; }
.md-render code     { background: #21262d; color: #79c0ff; padding: 1px 6px; border-radius: 4px; font-size: 11px; font-family: monospace; }
.md-render pre      { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 10px; overflow-x: auto; }
.md-render pre code { background: none; padding: 0; color: #7ee787; }
.md-render h1, .md-render h2, .md-render h3 { color: #e6edf3; margin: 10px 0 6px; }
.md-render a        { color: #58a6ff; }
.md-render blockquote { border-left: 3px solid #30363d; padding-left: 10px; color: #8b949e; margin: 6px 0; }
</style>
<script>
// Render semua elemen .md-render setelah DOM siap
document.addEventListener('DOMContentLoaded', function () {
    marked.setOptions({ breaks: true, gfm: true });
    document.querySelectorAll('.md-render[data-md]').forEach(function (el) {
        var text = el.getAttribute('data-md') || '';
        el.innerHTML = marked.parse(text);
        el.removeAttribute('data-md');
    });
});

function openModal(id) {
    document.getElementById('modal-' + id).style.display = 'block';
    document.body.style.overflow = 'hidden';
}
function closeModal(id) {
    document.getElementById('modal-' + id).style.display = 'none';
    document.body.style.overflow = '';
}
function toggleRaw(id) {
    const pre = document.getElementById('raw-' + id);
    const btn = pre.previousElementSibling;
    const visible = pre.style.display !== 'none';
    pre.style.display = visible ? 'none' : 'block';
    btn.innerHTML = (visible ? '&#x25B6;' : '&#x25BC;') + ' Lihat Raw JSON';
}
document.addEventListener('click', function(e) {
    if (e.target.style && e.target.style.position === 'fixed' && e.target.id && e.target.id.startsWith('modal-')) {
        e.target.style.display = 'none';
        document.body.style.overflow = '';
    }
});
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        document.querySelectorAll('[id^="modal-"]').forEach(function(m) {
            m.style.display = 'none';
        });
        document.body.style.overflow = '';
    }
});
</script>
@endpush
