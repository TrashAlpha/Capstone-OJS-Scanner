@extends('layouts.dashboard')

@section('page-title', 'Run Scan')

@section('content')
<div class="page-title">Run Scan</div>
<div class="page-sub">Masukkan target OJS untuk memulai pemindaian keamanan</div>

<div style="display:grid; grid-template-columns:1fr 1fr; gap:24px; margin-top:1rem;">

    {{-- FORM CARD --}}
    <div style="background:#161b22; border:1px solid #21262d; border-radius:10px; padding:1.5rem;">
        <h3 style="font-size:13px; font-weight:600; color:#e6edf3; margin-bottom:1.5rem; padding-bottom:0.75rem; border-bottom:1px solid #21262d;">
            Target Configuration
        </h3>

        <form method="POST" action="#" id="scanForm">
            @csrf

            {{-- URL OJS --}}
            <div style="margin-bottom:1.25rem;">
                <label style="display:block; font-size:11px; color:#8b949e; margin-bottom:6px; text-transform:uppercase; letter-spacing:0.5px;">
                    OJS URL <span style="color:#f85149;">*</span>
                </label>
                <input type="url" name="ojs_url" placeholder="https://journal.example.ac.id"
                    required
                    style="width:100%; background:#0d1117; border:1px solid #30363d; color:#e6edf3; padding:8px 12px; border-radius:8px; font-size:13px; outline:none;">
                <div style="font-size:11px; color:#484f58; margin-top:4px;">URL lengkap platform OJS yang akan di-scan</div>
            </div>

            {{-- DIVIDER --}}
            <div style="border-top:1px solid #21262d; margin:1.25rem 0; position:relative;">
                <span style="position:absolute; top:-9px; left:50%; transform:translateX(-50%); background:#161b22; padding:0 8px; font-size:11px; color:#484f58;">
                    Kredensial Admin (opsional)
                </span>
            </div>

            {{-- USERNAME --}}
            <div style="margin-bottom:1rem;">
                <label style="display:block; font-size:11px; color:#8b949e; margin-bottom:6px; text-transform:uppercase; letter-spacing:0.5px;">
                    Username Admin
                </label>
                <input type="text" name="admin_username" placeholder="admin"
                    style="width:100%; background:#0d1117; border:1px solid #30363d; color:#e6edf3; padding:8px 12px; border-radius:8px; font-size:13px; outline:none;">
            </div>

            {{-- PASSWORD --}}
            <div style="margin-bottom:1.5rem;">
                <label style="display:block; font-size:11px; color:#8b949e; margin-bottom:6px; text-transform:uppercase; letter-spacing:0.5px;">
                    Password Admin
                </label>
                <div style="position:relative;">
                    <input type="password" name="admin_password" placeholder="••••••••" id="passwordInput"
                        style="width:100%; background:#0d1117; border:1px solid #30363d; color:#e6edf3; padding:8px 40px 8px 12px; border-radius:8px; font-size:13px; outline:none;">
                    <button type="button" onclick="togglePassword()"
                        style="position:absolute; right:10px; top:50%; transform:translateY(-50%); background:none; border:none; color:#8b949e; cursor:pointer; font-size:11px;">
                        SHOW
                    </button>
                </div>
            </div>

            {{-- SCAN TYPE --}}
            <div style="margin-bottom:1.5rem;">
                <label style="display:block; font-size:11px; color:#8b949e; margin-bottom:8px; text-transform:uppercase; letter-spacing:0.5px;">
                    Scan Type
                </label>
                <div style="display:flex; gap:8px;">
                    <label style="flex:1; background:#0d1117; border:1px solid #30363d; border-radius:8px; padding:8px 12px; cursor:pointer; display:flex; align-items:center; gap:8px; font-size:12px;">
                        <input type="radio" name="scan_type" value="external" checked> External Only
                    </label>
                    <label style="flex:1; background:#0d1117; border:1px solid #30363d; border-radius:8px; padding:8px 12px; cursor:pointer; display:flex; align-items:center; gap:8px; font-size:12px;">
                        <input type="radio" name="scan_type" value="internal"> Internal Only
                    </label>
                    <label style="flex:1; background:#0d1117; border:1px solid #30363d; border-radius:8px; padding:8px 12px; cursor:pointer; display:flex; align-items:center; gap:8px; font-size:12px;">
                        <input type="radio" name="scan_type" value="full"> Full Scan
                    </label>
                </div>
            </div>

            {{-- SUBMIT --}}
            <button type="submit"
                style="width:100%; background:#1f6feb; border:none; color:#fff; padding:10px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer;">
                Start Scan
            </button>
        </form>
    </div>

    {{-- INFO CARD --}}
    <div style="display:flex; flex-direction:column; gap:16px;">

        <div style="background:#161b22; border:1px solid #21262d; border-radius:10px; padding:1.25rem;">
            <div style="font-size:12px; font-weight:600; color:#e6edf3; margin-bottom:0.75rem;">External Scan</div>
            <div style="font-size:11px; color:#8b949e; line-height:1.6;">
                Scanning dari luar tanpa login. Mencakup directory fuzzing, version scan, security header audit, subdomain discovery, dan public endpoint injection.
            </div>
        </div>

        <div style="background:#161b22; border:1px solid #21262d; border-radius:10px; padding:1.25rem;">
            <div style="font-size:12px; font-weight:600; color:#e6edf3; margin-bottom:0.75rem;">Internal Scan</div>
            <div style="font-size:11px; color:#8b949e; line-height:1.6;">
                Membutuhkan kredensial admin. Mencakup file upload vulnerability, broken access control, IDOR check, parameter injection, dan info disclosure.
            </div>
            <div style="font-size:11px; color:#f0883e; margin-top:8px;">
                Username & password diperlukan untuk mode ini.
            </div>
        </div>

        <div style="background:#161b22; border:1px solid #21262d; border-radius:10px; padding:1.25rem;">
            <div style="font-size:12px; font-weight:600; color:#e6edf3; margin-bottom:0.75rem;">Full Scan</div>
            <div style="font-size:11px; color:#8b949e; line-height:1.6;">
                Menjalankan External + Internal scan secara berurutan. Hasil paling komprehensif, membutuhkan kredensial admin.
            </div>
        </div>

    </div>
</div>

@endsection

@push('scripts')
<script>
function togglePassword() {
    const input = document.getElementById('passwordInput');
    const btn = event.target;
    if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = 'HIDE';
    } else {
        input.type = 'password';
        btn.textContent = 'SHOW';
    }
}
</script>
@endpush