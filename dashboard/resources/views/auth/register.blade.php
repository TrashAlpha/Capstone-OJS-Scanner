<!DOCTYPE html>
<html lang="en" id="htmlRoot">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Register — OJS Security Scanner</title>
  @vite(['resources/css/app.css', 'resources/js/app.js'])
</head>
<body class="auth-body">

<div class="auth-toggle" onclick="toggleTheme()">
  <svg id="iconSun" viewBox="0 0 24 24" style="display:none"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
  <svg id="iconMoon" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
</div>

<div class="auth-card">
  <div class="auth-logo">
      <img src="/images/logo.png" alt="OJS Security Scanner"
          style="width:64px; height:64px; object-fit:contain; margin-bottom:10px; display:block; margin-left:auto; margin-right:auto;">
      <div class="auth-logo-title">OJS Security Scanner</div>
      <div class="auth-logo-sub">Create a new account</div>
  </div>

  <hr class="auth-divider">

  <form method="POST" action="{{ route('register') }}">
    @csrf
    <div class="form-group">
      <label class="form-label">Full Name</label>
      <input type="text" name="name" class="form-input" placeholder="Your name" value="{{ old('name') }}" required autofocus>
      @error('name')<div class="form-error">{{ $message }}</div>@enderror
    </div>
    <div class="form-group">
      <label class="form-label">Email</label>
      <input type="email" name="email" class="form-input" placeholder="you@example.com" value="{{ old('email') }}" required>
      @error('email')<div class="form-error">{{ $message }}</div>@enderror
    </div>
    <div class="form-group">
      <label class="form-label">Password</label>
      <input type="password" name="password" class="form-input" placeholder="Min. 8 characters" required>
      @error('password')<div class="form-error">{{ $message }}</div>@enderror
    </div>
    <div class="form-group">
      <label class="form-label">Confirm Password</label>
      <input type="password" name="password_confirmation" class="form-input" placeholder="Repeat password" required>
    </div>
    <button type="submit" class="btn-primary">Create Account</button>
  </form>

  <div class="auth-footer">
    Already have an account? <a href="{{ route('login') }}">Sign in here</a>
  </div>
</div>

</body>
</html>