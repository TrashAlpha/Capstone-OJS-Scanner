@extends('layouts.dashboard')

@section('page-title', 'Telegram Alerts')

@section('content')
<div class="page-title">Telegram Alerts</div>
<div class="page-sub">Receive scan notifications directly in Telegram</div>

@if (session('status'))
<div style="margin:16px 0; background:#3fb95015; border:1px solid #3fb95044; color:#7ee787; padding:10px 12px; border-radius:8px; font-size:12px;">
  {{ session('status') }}
</div>
@endif

@if ($errors->any())
<div style="margin:16px 0; background:#f8514915; border:1px solid #f8514944; color:#fdaeb7; padding:10px 12px; border-radius:8px; font-size:12px;">
  {{ $errors->first() }}
</div>
@endif

<div style="display:grid; grid-template-columns:1.2fr .8fr; gap:24px; margin-top:1rem;">
  <div style="background:#161b22; border:1px solid #21262d; border-radius:10px; padding:1.5rem;">
    <h3 style="font-size:13px; font-weight:600; color:#e6edf3; margin-bottom:1rem;">Connect your Telegram</h3>

    <form method="POST" action="{{ route('integrations.telegram.update') }}">
      @csrf
      @method('PUT')

      <label style="display:block; font-size:11px; color:#8b949e; margin-bottom:6px; text-transform:uppercase; letter-spacing:0.5px;">
        Telegram Chat ID
      </label>
      <input
        type="text"
        name="telegram_chat_id"
        value="{{ old('telegram_chat_id', $user->telegram_chat_id) }}"
        placeholder="Example: 123456789"
        style="width:100%; background:#0d1117; border:1px solid #30363d; color:#e6edf3; padding:8px 12px; border-radius:8px; font-size:13px; outline:none;"
      >
      <div style="font-size:11px; color:#8b949e; margin-top:8px; line-height:1.6;">
        Enter the Telegram Chat ID that should receive scan alerts. If you do not know your Chat ID yet, open our bot in Telegram and press <strong>Start</strong> first. The bot can only send you alerts after you have started the chat.
      </div>

      <div style="margin-top:1.25rem; display:flex; gap:10px; flex-wrap:wrap;">
        <button type="submit" style="background:#1f6feb; border:none; color:#fff; padding:10px 16px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer;">
          Save Telegram Settings
        </button>
        <a href="{{ route('scanner.run') }}" style="background:#21262d; border:1px solid #30363d; color:#e6edf3; padding:10px 16px; border-radius:8px; text-decoration:none; font-size:13px;">
          Back to Run Scan
        </a>
      </div>
    </form>

    <form method="POST" action="{{ route('integrations.telegram.test') }}" style="margin-top:12px;">
      @csrf
      <button type="submit" style="background:#238636; border:none; color:#fff; padding:10px 16px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer;">
        Send Test Message
      </button>
    </form>
  </div>

  <div style="display:flex; flex-direction:column; gap:16px;">
    <div style="background:#161b22; border:1px solid #21262d; border-radius:10px; padding:1.25rem;">
      <div style="font-size:12px; font-weight:600; color:#e6edf3; margin-bottom:0.75rem;">How to find your Chat ID</div>
      <ol style="margin:0; padding-left:18px; color:#8b949e; font-size:11px; line-height:1.8;">
        <li>Open Telegram.</li>
        <li>
          Search for our bot
          @if ($botUsername)
            <a href="https://t.me/{{ $botUsername }}" target="_blank" rel="noopener noreferrer" style="color:#58a6ff; text-decoration:none;">&#64;{{ $botUsername }}</a>.
          @else
            from your Telegram search.
          @endif
        </li>
        <li>Press <strong>Start</strong> or send <code>/start</code>.</li>
        <li>The bot service will reply with your Telegram Chat ID automatically.</li>
        <li>Copy that Chat ID and paste it on this page.</li>
      </ol>
    </div>

    <div style="background:#161b22; border:1px solid #21262d; border-radius:10px; padding:1.25rem;">
      <div style="font-size:12px; font-weight:600; color:#e6edf3; margin-bottom:0.75rem;">Current status</div>
      <div style="font-size:11px; color:#8b949e; line-height:1.6;">
        @if ($user->telegram_notifications_enabled && $user->telegram_chat_id)
          Alerts are enabled for Chat ID <span class="mono">{{ $user->telegram_chat_id }}</span>.
        @else
          Telegram alerts are not connected yet.
        @endif
      </div>
      <div style="margin-top:10px; font-size:11px; color:#8b949e; line-height:1.7;">
        <div>Bot username detected: <span class="mono">{{ $botUsername ?: 'NOT DETECTED' }}</span></div>
        <div>Bot token detected: <span class="mono">{{ $botTokenPresent ? 'YES' : 'NO' }}</span></div>
      </div>
      @if ($botUsername)
      <div style="margin-top:10px; font-size:11px;">
        <a href="https://t.me/{{ $botUsername }}" target="_blank" rel="noopener noreferrer" style="color:#58a6ff; text-decoration:none;">
          Open &#64;{{ $botUsername }} in Telegram
        </a>
      </div>
      @endif
    </div>

    <div style="background:#161b22; border:1px solid #21262d; border-radius:10px; padding:1.25rem;">
      <div style="font-size:12px; font-weight:600; color:#e6edf3; margin-bottom:0.75rem;">No webhook needed</div>
      <div style="font-size:11px; color:#8b949e; line-height:1.7;">
        This project uses a simple Telegram bot service with polling, so you do not need to configure a public webhook URL.
      </div>
    </div>
  </div>
</div>
@endsection
