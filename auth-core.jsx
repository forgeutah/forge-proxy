/* global React */
/* eslint-disable no-unused-vars */

// =====================================================================
// Forge Auth Proxy — sign-in app
// 6 states × 3 layout variants, with simulated Slack OAuth round-trip.
// =====================================================================

const { useState, useEffect, useRef, useMemo, useCallback } = React;

// ── State definitions ───────────────────────────────────────────────────────
const STATES = [
  { id: 'logged-out',   label: 'Logged out' },
  { id: 'connecting',   label: 'Connecting' },
  { id: 'success',      label: 'Success' },
  { id: 'error',        label: 'Error' },
  { id: 'unauthorized', label: 'Unauthorized' },
  { id: 'logged-in',    label: 'Already signed in' },
];

// Steps for the simulated OAuth flow shown in 'connecting'.
const FLOW_STEPS = [
  { ms: 0,    text: 'Initiating handshake with auth.forgeutah.tech', tag: 'auth-proxy' },
  { ms: 550,  text: 'Redirecting to slack.com/oauth/v2/authorize',   tag: 'oauth' },
  { ms: 1250, text: 'Awaiting workspace approval (forge-utah.slack.com)', tag: 'oauth' },
  { ms: 2150, text: 'Verifying membership in #forge-utah',           tag: 'authz' },
  { ms: 2750, text: 'Issuing signed session token',                  tag: 'session' },
];

const APPS = {
  'deuce.forgeutah.tech':    { name: 'Deuce',    blurb: 'Volunteer time tracking' },
  'platform.forgeutah.tech': { name: 'Platform', blurb: 'Member dashboard' },
};

// ── Forge mark (icon-only flame + cog) ──────────────────────────────────────
function ForgeMark({ size = 24, glow = true }) {
  return (
    <svg
      viewBox="0 0 212.7 323.81"
      width={size}
      height={size * (323.81 / 212.7)}
      aria-label="Forge Utah"
      style={{
        display: 'block',
        flexShrink: 0,
        filter: glow ? 'drop-shadow(0 0 10px rgba(192,64,88,0.5))' : 'none',
      }}
    >
      <path fill="var(--forge-cog)" d="M211.66,234.18c.52-3.14.78-6.53,1.05-9.93l-8.62-2.35c-19.34,34.23-55.92,57.23-98.25,57.23s-76.56-21.69-96.42-54.09l-9.41,3.14c.26,3.4.78,6.53,1.57,9.67h10.97c.78,3.66,1.83,7.58,3.14,10.97l-9.15,6.27c1.31,3.14,2.61,6.01,3.92,9.15l10.71-2.61c1.83,3.4,3.66,6.79,6.01,9.93l-7.32,8.36c1.83,2.61,3.92,5.23,6.27,7.84l9.67-5.49c2.61,2.87,5.49,5.49,8.36,8.1l-4.96,9.93c2.61,2.09,5.23,3.92,7.84,5.75l7.84-7.58c3.13,2.09,6.53,3.92,9.93,5.49l-2.09,10.71c2.87,1.31,6.01,2.61,9.15,3.66l5.49-9.41c3.66,1.04,7.32,2.09,11.24,2.87l.78,10.97c3.14.52,6.53.78,9.93,1.05l2.87-10.71h4.18c2.61,0,4.96,0,7.32-.26l3.66,10.45c3.4-.26,6.53-.78,9.67-1.57v-10.98c3.66-.78,7.58-1.83,10.97-3.13l6.27,9.15c3.13-1.31,6.01-2.61,9.15-3.92l-2.61-10.71c3.4-1.83,6.79-3.66,9.93-6.01l8.36,7.32c2.61-1.83,5.23-3.92,7.58-6.27l-5.49-9.67c2.87-2.61,5.49-5.49,8.1-8.36l9.93,4.96c2.09-2.61,3.92-5.23,5.75-7.84l-7.58-7.84c2.09-3.14,3.92-6.53,5.49-9.93l10.71,2.09c1.31-2.87,2.61-6.01,3.66-9.15l-9.41-5.49c1.05-3.66,2.09-7.32,2.87-11.24l10.97-.52ZM211.66,234.18"/>
      <path fill="var(--forge-flame)" d="M108.87,0s39.08,66.53-21.54,116.9c-55.54,46.26-19.92,111.09,27.12,103.32,47.03-8.02,45.58-53.99,19.08-70.53-26.49-16.27-24.28-41.2-6.08-58.09,0,0-16.17,15.24,19.27,33.01,35.44,17.77,57.69,60.61,33.65,103.34-24.04,42.73-97.93,52.54-137.7,9.83C20.33,213.79.3,153.35,51.49,109.6,96.59,70.53,114.94,50.76,108.87,0h0ZM108.87,0"/>
      <path fill="var(--forge-flame)" d="M153.47,116.57s-29.13-9.9-18.83-42.18c10.08-31.23-5.69-40.58-5.69-40.58,0,0,26.75,9.2,18.01,41.17-7.41,25.64,6.52,41.6,6.52,41.6h0ZM153.47,116.57"/>
    </svg>
  );
}

// ── Slack glyph ─────────────────────────────────────────────────────────────
function SlackGlyph() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path fill="#E01E5A" d="M5 15.5a2 2 0 1 1-2-2h2v2zm1 0a2 2 0 1 1 4 0v5a2 2 0 1 1-4 0v-5z"/>
      <path fill="#36C5F0" d="M8.5 5a2 2 0 1 1 2-2v2h-2zm0 1a2 2 0 1 1 0 4h-5a2 2 0 1 1 0-4h5z"/>
      <path fill="#2EB67D" d="M19 8.5a2 2 0 1 1 2 2h-2v-2zm-1 0a2 2 0 1 1-4 0v-5a2 2 0 1 1 4 0v5z"/>
      <path fill="#ECB22E" d="M15.5 19a2 2 0 1 1-2 2v-2h2zm0-1a2 2 0 1 1 0-4h5a2 2 0 1 1 0 4h-5z"/>
    </svg>
  );
}

// ── shared atoms ─────────────────────────────────────────────────────────────
function ProgressDots() {
  return <span className="progress-dots" aria-hidden="true"><span /><span /><span /></span>;
}
function Spin() { return <span className="spin" aria-hidden="true">◴</span>; }

function SlackButton({ disabled, onClick, label = 'Continue with Slack' }) {
  return (
    <button type="button" className="slack-btn" disabled={disabled} onClick={onClick}>
      <SlackGlyph />
      <span>{label}</span>
    </button>
  );
}

function WhySlack() {
  return (
    <div className="why-slack">
      <details>
        <summary>Why Slack?</summary>
        <div className="why-body">
          The Forge Utah workspace is where the community already lives — meetups,
          job posts, project channels. We use it as our identity provider so there's
          no extra account to manage. The proxy issues a short-lived session and
          forwards you to the requested app. Your Slack credentials never touch
          our servers.
        </div>
      </details>
    </div>
  );
}

function JoinLink() {
  return (
    <p className="join-link">
      Not in our Slack yet?{' '}
      <a href="https://join.slack.com/t/forgeutah/shared_invite/zt-pietaeqb-HetfD2OIzn1RHtDtV~CH5g">
        Join the workspace →
      </a>
    </p>
  );
}

function DestRow({ host, badge = 'proxied' }) {
  return (
    <div className="dest-row">
      <span className="lbl">dest</span>
      <span className="arrow">→</span>
      <span className="host">{host}</span>
      <span className="badge">{badge}</span>
    </div>
  );
}

function UserChip({ user, onSwitch }) {
  const initials = user.name.split(' ').map(s => s[0]).slice(0, 2).join('');
  return (
    <div className="user-chip">
      <div className="avatar">{initials}</div>
      <div className="who">
        <span className="name">{user.name}</span>
        <span className="handle">@{user.handle} · forge-utah.slack.com</span>
      </div>
      <button type="button" className="switch" onClick={onSwitch}>switch</button>
    </div>
  );
}

// status panel rendering a log of rows
function StatePanel({ variant, title, status, rows, extra, statusGlyph }) {
  const cls = variant === 'err' ? 'state-panel err-block'
            : variant === 'warn' ? 'state-panel warn-block'
            : variant === 'ok' ? 'state-panel ok-block'
            : 'state-panel';
  return (
    <div className={cls}>
      <div className="head">
        <span className="label">
          {statusGlyph}
          {title}
        </span>
        <span>{status}</span>
      </div>
      <div className="log">
        {rows.map((r, i) => (
          <div key={i} className={`row ${r.kind || ''}`}>
            <span className="glyph">{r.glyph || '·'}</span>
            <span className="msg" dangerouslySetInnerHTML={{ __html: r.html }} />
          </div>
        ))}
      </div>
      {extra}
    </div>
  );
}

// ── State machine for the simulated flow ────────────────────────────────────
function useAuthFlow(initialState, hostApp) {
  const [state, setState] = useState(initialState);
  const [stepIdx, setStepIdx] = useState(-1);
  const [countdown, setCountdown] = useState(3);
  const timeouts = useRef([]);
  const intervals = useRef([]);

  const clearAll = useCallback(() => {
    timeouts.current.forEach(t => clearTimeout(t));
    intervals.current.forEach(t => clearInterval(t));
    timeouts.current = [];
    intervals.current = [];
  }, []);

  // When the externally-controlled state changes (via tweak), sync.
  useEffect(() => {
    setState(initialState);
    setStepIdx(-1);
    setCountdown(3);
    clearAll();
    // when state becomes 'connecting' externally, also schedule steps
    if (initialState === 'connecting') {
      kickOffSteps();
    }
    if (initialState === 'success') {
      startCountdown();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialState]);

  const kickOffSteps = useCallback(() => {
    clearAll();
    setStepIdx(-1);
    FLOW_STEPS.forEach((step, i) => {
      const t = setTimeout(() => setStepIdx(i), step.ms);
      timeouts.current.push(t);
    });
    // finish: success
    const done = setTimeout(() => {
      setState('success');
      startCountdown();
    }, FLOW_STEPS[FLOW_STEPS.length - 1].ms + 700);
    timeouts.current.push(done);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const startCountdown = useCallback(() => {
    setCountdown(3);
    const iv = setInterval(() => {
      setCountdown(c => {
        if (c <= 1) { clearInterval(iv); return 0; }
        return c - 1;
      });
    }, 900);
    intervals.current.push(iv);
  }, []);

  const startConnecting = useCallback(() => {
    setState('connecting');
    kickOffSteps();
  }, [kickOffSteps]);

  useEffect(() => () => clearAll(), [clearAll]);

  return { state, stepIdx, countdown, startConnecting };
}

// ── State content (the inner body) — reusable across all 3 variants ─────────
function StateContent({ flow, app, host, withAscii, layout }) {
  const { state, stepIdx, countdown, startConnecting } = flow;
  const appInfo = APPS[host] || APPS['deuce.forgeutah.tech'];

  // LOGGED-OUT
  if (state === 'logged-out') {
    return (
      <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <DestRow host={host} />
        <SlackButton onClick={startConnecting} />
        <WhySlack />
        <JoinLink />
      </div>
    );
  }

  // CONNECTING
  if (state === 'connecting') {
    const rows = FLOW_STEPS.slice(0, stepIdx + 1).map((s, i) => {
      const isCurrent = i === stepIdx;
      return {
        kind: isCurrent ? 'run' : 'ok',
        glyph: isCurrent ? <span className="spin">◴</span> : '✓',
        html: `<span style="color:var(--fg-dim);font-size:11px;margin-right:8px">[${s.tag}]</span> ${s.text}${isCurrent ? '…' : ''}`,
      };
    });
    return (
      <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <DestRow host={host} badge="redirecting" />
        <StatePanel
          variant="info"
          title="Authenticating"
          status={<ProgressDots />}
          statusGlyph={<span className="spin" style={{ color: 'var(--term-cyan)' }}>◴</span>}
          rows={rows.length ? rows : [{ kind: 'run', glyph: '·', html: 'Opening Slack…' }]}
        />
        <p style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--fg-dim)', margin: 0, textAlign: 'center' }}>
          Don't see Slack? <a href="#" style={{ color: 'var(--accent)', textDecoration: 'none', fontWeight: 600 }}>Re-open authorization →</a>
        </p>
      </div>
    );
  }

  // SUCCESS
  if (state === 'success') {
    return (
      <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <DestRow host={host} badge="authorized" />
        <StatePanel
          variant="ok"
          title="Authenticated"
          status="200 OK"
          statusGlyph={<span style={{ color: 'var(--term-green)' }}>●</span>}
          rows={[
            { kind: 'ok', glyph: '✓', html: 'Slack OAuth granted (<b>workspace: forge-utah</b>)' },
            { kind: 'ok', glyph: '✓', html: 'Session token signed (<code>HS256</code>, 8h ttl)' },
            { kind: 'ok', glyph: '✓', html: `Forwarding to <code>${host}</code>` },
          ]}
          extra={
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, paddingTop: 8, borderTop: '1px dashed var(--border)' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--fg-dim)' }}>
                Redirecting in <b style={{ color: 'var(--term-green)' }}>{countdown}s</b>…
              </span>
              <a href="#" className="btn-primary" style={{ padding: '8px 14px', fontSize: 12 }}>
                Continue now →
              </a>
            </div>
          }
        />
      </div>
    );
  }

  // ERROR
  if (state === 'error') {
    return (
      <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <DestRow host={host} badge="blocked" />
        <StatePanel
          variant="err"
          title="Authentication failed"
          status="401"
          statusGlyph={<span style={{ color: 'var(--term-error)' }}>✕</span>}
          rows={[
            { kind: 'err', glyph: '✕', html: 'Slack returned <code>invalid_grant</code>' },
            { kind: 'warn', glyph: '!', html: 'Authorization code expired or already used' },
            { kind: 'info', glyph: 'ℹ', html: 'No session was created. You can safely retry.' },
          ]}
          extra={
            <div style={{ display: 'flex', gap: 8, paddingTop: 8 }}>
              <button type="button" className="btn-primary" onClick={() => startConnecting()} style={{ padding: '10px 14px', fontSize: 12 }}>
                ↻ Try again
              </button>
              <a href="#" className="btn-ghost" style={{ padding: '10px 14px', fontSize: 12 }}>
                View error log
              </a>
            </div>
          }
        />
        <p style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--fg-dim)', margin: 0 }}>
          ref: <code style={{ color: 'var(--term-cyan)', background: 'transparent' }}>err_8f2a91c4-b0e7</code>
        </p>
      </div>
    );
  }

  // UNAUTHORIZED
  if (state === 'unauthorized') {
    return (
      <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <DestRow host={host} badge="403" />
        <StatePanel
          variant="warn"
          title="Not a member"
          status="403"
          statusGlyph={<span style={{ color: 'var(--term-amber)' }}>⚠</span>}
          rows={[
            { kind: 'warn', glyph: '!', html: 'You signed in as <b>jamie@example.com</b>' },
            { kind: 'warn', glyph: '!', html: 'But that account isn\'t in the <code>forge-utah</code> workspace.' },
            { kind: 'info', glyph: 'ℹ', html: 'Forge apps are open to everyone — Slack membership is free.' },
          ]}
          extra={
            <div style={{ display: 'flex', gap: 8, paddingTop: 8, flexWrap: 'wrap' }}>
              <a href="https://join.slack.com/t/forgeutah/shared_invite/zt-pietaeqb-HetfD2OIzn1RHtDtV~CH5g"
                 className="btn-primary" style={{ padding: '10px 14px', fontSize: 12 }}>
                Join Forge Utah Slack →
              </a>
              <button type="button" className="btn-ghost" onClick={() => startConnecting()} style={{ padding: '10px 14px', fontSize: 12 }}>
                Use a different account
              </button>
            </div>
          }
        />
      </div>
    );
  }

  // LOGGED-IN
  if (state === 'logged-in') {
    return (
      <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <DestRow host={host} badge="cached" />
        <UserChip
          user={{ name: 'Daniel Riley', handle: 'driley' }}
          onSwitch={() => startConnecting()}
        />
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, padding: 12, background: 'var(--bg-canvas)', border: '1px solid var(--border)', borderRadius: 2 }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: '0.12em', textTransform: 'uppercase', color: 'var(--fg-dim)' }}>
            Active session
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--fg-muted)', display: 'flex', justifyContent: 'space-between' }}>
            <span>Expires</span><span style={{ color: 'var(--fg-strong)' }}>in 6h 42m</span>
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--fg-muted)', display: 'flex', justifyContent: 'space-between' }}>
            <span>Issued</span><span style={{ color: 'var(--fg-strong)' }}>1h 18m ago · Salt Lake City</span>
          </div>
        </div>
        <a href="#" className="btn-primary" style={{ width: '100%' }}>
          Continue to {appInfo.name} →
        </a>
        <p style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--fg-dim)', margin: 0, textAlign: 'center' }}>
          Going somewhere else? <a href="#" style={{ color: 'var(--accent)', textDecoration: 'none', fontWeight: 600 }}>Sign out</a>
        </p>
      </div>
    );
  }

  return null;
}

// expose to other scripts
Object.assign(window, { useAuthFlow, StateContent, APPS, FLOW_STEPS, SlackGlyph, SlackButton, JoinLink, WhySlack, DestRow, ForgeMark });
