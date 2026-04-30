@extends('layouts.dashboard')

@section('page-title', 'Reports')

@section('content')
<div class="page-title">Reports</div>
<div class="page-sub">Laporan hasil analisis keamanan OJS</div>

<div style="background:#161b22; border:1px solid #21262d; border-radius:10px; padding:2rem; margin-top:1rem; text-align:center;">
    <div style="font-size:2rem; margin-bottom:1rem;">📄</div>
    <div style="font-size:14px; color:#8b949e; margin-bottom:1.5rem;">
        Belum ada laporan yang tersedia. Jalankan scan terlebih dahulu untuk menghasilkan laporan.
    </div>
    <a href="{{ route('scanner.run') }}" style="background:#1f6feb22; border:1px solid #1f6feb44; color:#58a6ff; padding:8px 20px; border-radius:8px; text-decoration:none; font-size:13px;">
        Run Scan
    </a>
</div>
@endsection