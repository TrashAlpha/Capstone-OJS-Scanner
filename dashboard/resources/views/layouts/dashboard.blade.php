<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OJS Security Scanner</title>
  @vite(['resources/css/app.css', 'resources/js/app.js'])
</head>
<body>

<div class="layout">
    {{-- SIDEBAR --}}
    <aside class="sidebar">
      <div class="sidebar-logo">
          <img src="/images/logo.png" alt="OJS Security Scanner"
              style="width:48px; height:48px; object-fit:contain; margin-bottom:6px;">
          <div class="sidebar-logo-title">OJS Security</div>
          <div class="sidebar-logo-sub">Scanner v1.0</div>
      </div>

    <div class="sidebar-section">Main</div>
    <a href="{{ route('dashboard') }}" class="sidebar-link {{ request()->routeIs('dashboard') ? 'active' : '' }}">
      <svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
      Dashboard
    </a>

    <div class="sidebar-section">Scanner</div>
    <a href="{{ route('scanner.logs') }}" class="sidebar-link {{ request()->routeIs('scanner.logs') ? 'active' : '' }}">
      <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      Scan Logs
    </a>
    <a href="{{ route('scanner.run') }}" class="sidebar-link {{ request()->routeIs('scanner.run') ? 'active' : '' }}">
      <svg viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg>
      Run Scan
    </a>

    <div class="sidebar-section">Reports</div>
    <a href="{{ route('reports.index') }}" class="sidebar-link {{ request()->routeIs('reports.*') ? 'active' : '' }}">
      <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
      Reports
    </a>
  </aside>

  {{-- MAIN AREA --}}
  <div class="main">

    {{-- TOPBAR --}}
    <header class="topbar">
      <div class="topbar-title">@yield('page-title', 'Dashboard')</div>
      <div class="topbar-right">
        <span class="topbar-date">{{ now()->format('d M Y') }}</span>
        <button class="topbar-btn" onclick="window.location='{{ route('scanner.run') }}'">+ Run Scan</button>
        {{-- THEME TOGGLE --}}
        <div class="theme-toggle" onclick="toggleTheme()">
            <svg id="iconSun" viewBox="0 0 24 24" style="display:none"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
            <svg id="iconMoon" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
        </div>
        <div class="avatar-wrap">
          <div class="avatar" id="avatarBtn" onclick="toggleDropdown()">
            {{ strtoupper(substr(auth()->user()->name, 0, 2)) }}
          </div>
          <div class="dropdown" id="profileDropdown">
            <div class="dropdown-header">
              <div class="name">{{ auth()->user()->name }}</div>
              <div class="email">{{ auth()->user()->email }}</div>
            </div>
            <a href="{{ route('profile.edit') }}" class="dropdown-item">
              <svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
              My Profile
            </a>
            <form method="POST" action="{{ route('logout') }}">
              @csrf
              <button type="submit" class="dropdown-item logout">
                <svg viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                Logout
              </button>
            </form>
          </div>
        </div>
      </div>
    </header>

    {{-- CONTENT --}}
    <div class="content">
      @yield('content')
    </div>

  </div>
</div>

<script>
function toggleDropdown() {
  document.getElementById('profileDropdown').classList.toggle('open');
}
document.addEventListener('click', function(e) {
  if (!e.target.closest('.avatar-wrap')) {
    document.getElementById('profileDropdown').classList.remove('open');
  }
});
</script>
@stack('scripts')
</body>
</html>