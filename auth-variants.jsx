/* global React, StateContent, APPS */
/* eslint-disable no-unused-vars */

// =====================================================================
// Forge Auth Proxy — 3 layout variants
// Each variant accepts: { flow, host, app, withAscii }
// =====================================================================

// ── Variant A: CARD ─────────────────────────────────────────────────────────
function VariantCard({ flow, host, withAscii }) {
  return (
    <div className="auth-stage">
      <div className="auth-dotgrid" />
      <div className="auth-glow" />
      <TopBar />
      <div className="auth-main">
        <div className={`va-card ${withAscii ? 'with-ascii' : ''}`}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
            <div className="logo-row">
              <ForgeMark size={32} />
              <div>
                <div className="text">forge<span className="accent">/</span>auth</div>
                <span className="sub">proxy · v1.4.0</span>
              </div>
            </div>
            <span className="pill idle"><span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--term-green)', boxShadow: '0 0 6px var(--term-green)' }} /> healthy</span>
          </div>

          <div>
            <span className="eyebrow">sign in</span>
            <h1 style={{ marginTop: 8 }}>
              {flow.state === 'logged-in' ? <>Welcome back<span className="cursor" /></> :
               flow.state === 'success' ? <>You're in<span className="cursor" /></> :
               flow.state === 'error' ? <>Something blew up</> :
               flow.state === 'unauthorized' ? <>Almost there</> :
               flow.state === 'connecting' ? <>Hold tight<span className="cursor" /></> :
               <>Sign in to continue<span className="cursor" /></>}
            </h1>
            <p className="lede">
              {flow.state === 'logged-out' && <>Forge Auth is the proxy in front of our apps. Sign in with Slack — we'll forward you to <code style={{ color: 'var(--term-cyan)', background: 'transparent', fontFamily: 'var(--font-mono)' }}>{host}</code>.</>}
              {flow.state === 'connecting' && <>Bouncing through Slack's OAuth flow. This usually takes a second or two.</>}
              {flow.state === 'success' && <>Session created. We're handing you off to the app now.</>}
              {flow.state === 'error' && <>The Slack OAuth handshake didn't complete. Your session wasn't touched.</>}
              {flow.state === 'unauthorized' && <>You're signed into Slack, but not into the Forge Utah workspace.</>}
              {flow.state === 'logged-in' && <>You've got a valid session. Continue on to the app, or sign out below.</>}
            </p>
          </div>

          <StateContent flow={flow} host={host} withAscii={withAscii} layout="card" />
        </div>
      </div>
      <FootBar />
    </div>
  );
}

// ── Variant B: TERMINAL ─────────────────────────────────────────────────────
function VariantTerminal({ flow, host, withAscii }) {
  const FLAME_ART = withAscii ? `
      ▲
     ▲▲▲
    ▲▲█▲▲           forge-auth v1.4.0
   ▲▲███▲▲          © Forge Utah Foundation — MIT
    █████          ────────────────────────────────
   ░░███░░          A reverse proxy with Slack OAuth
    ░░░░░           for the Forge community.` : null;

  return (
    <div className="auth-stage auth-scanlines">
      <div className="auth-glow" />
      <TopBar />
      <div className="auth-main">
        <div className="vb-term">
          <div className="vb-bar">
            <div className="dots"><span /><span /><span /></div>
            <div className="title">~ — <b>forge-auth</b> — login --provider=slack — 80×24</div>
            <div className="session">SESSION 8f2a91c4</div>
          </div>
          <div className="vb-body">
            {FLAME_ART && (
              <div className="vb-banner-row">
                <pre className="vb-flame">{FLAME_ART}</pre>
              </div>
            )}

            <div className="vb-line muted">
              <span className="stamp">12:34:08</span>
              <span className="tag">[boot]</span>
              auth-proxy ready · pid 1 · routes registered: <span style={{ color: 'var(--term-cyan)' }}>2</span>
            </div>
            <div className="vb-line">
              <span className="ps">user@laptop:~$</span>
              <span className="cmd">forge auth login </span>
              <span className="flag">--target</span>
              <span> </span>
              <span className="arg">{host}</span>
            </div>
            <div className="vb-line muted">
              <span className="stamp">12:34:09</span>
              <span className="tag">[router]</span>
              resolving <span style={{ color: 'var(--term-cyan)' }}>{host}</span> → upstream <span style={{ color: 'var(--term-amber)' }}>{(APPS[host] || {}).name || 'app'}</span>{' '}
              <span style={{ color: 'var(--term-green)' }}>OK</span>
            </div>
            <div className="vb-line muted">
              <span className="stamp">12:34:09</span>
              <span className="tag">[auth]</span>
              no session cookie — handing off to identity provider
            </div>

            <div style={{ marginTop: 4, padding: '4px 0' }}>
              <StateContent flow={flow} host={host} withAscii={withAscii} layout="terminal" />
            </div>

            <div className="vb-prompt" style={{ marginTop: 'auto' }}>
              <span className="ps">user@laptop:~$</span>
              <span className="typed" style={{ opacity: 0.4 }}>{flow.state === 'logged-out' ? '' : '_'}</span>
              <span className="cursor" />
            </div>
          </div>
        </div>
      </div>
      <FootBar />
    </div>
  );
}

// ── Variant C: SPLIT ────────────────────────────────────────────────────────
function VariantSplit({ flow, host, withAscii }) {
  const FLAME_ART = `
        ▲
       ▲▲▲
      ▲▲█▲▲
     ▲▲███▲▲
    ▲▲█████▲▲
     ▲▲███▲▲
      ▲███▲
       █▓█
      ╔═══╗
      ║ ⚙ ║
      ╚═══╝`;

  return (
    <div className="auth-stage">
      <div className="auth-glow" />
      <TopBar />
      <div className="auth-main">
        <div className="vc-split">
          <div className="vc-left">
            <div className="vc-brand">
              <ForgeMark size={30} />
              <div className="text">forge<span className="accent">/</span>auth</div>
            </div>

            <div className="vc-tag">&gt; one login. every forge app.</div>
            <h1 className="vc-lead">
              Built for the<br />
              <span className="em">builders.</span>
            </h1>
            <p className="vc-sub">
              Forge Auth is the gateway in front of every app we ship. Sign in once
              with the Slack you already use, get bounced to the right service.
              No extra accounts. No more passwords to forget.
            </p>

            <div className="vc-trust">
              <span className="item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                signed sessions
              </span>
              <span className="item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                slack-gated
              </span>
              <span className="item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
                open-source
              </span>
            </div>

            {withAscii && <pre className="vc-flame-art">{FLAME_ART}</pre>}
          </div>

          <div className="vc-right">
            <div className="small-eyebrow">&gt; auth.forgeutah.tech</div>
            <h2>
              {flow.state === 'logged-in' ? 'Welcome back.' :
               flow.state === 'success'   ? "You're in." :
               flow.state === 'error'     ? 'Auth failed.' :
               flow.state === 'unauthorized' ? 'Almost there.' :
               flow.state === 'connecting'   ? 'One sec…' :
               'Sign in to continue.'}
            </h2>
            <StateContent flow={flow} host={host} withAscii={withAscii} layout="split" />
          </div>
        </div>
      </div>
      <FootBar />
    </div>
  );
}

// ── Shared top/bottom chrome ────────────────────────────────────────────────
function TopBar() {
  return (
    <div className="auth-topbar">
      <span /> {/* spacer to keep meta right-aligned */}
      <div className="meta">
        <span className="stat"><span className="dot" /> all systems normal</span>
        <span style={{ color: 'var(--fg-disabled)' }}>·</span>
        <span>auth-proxy v1.4.0</span>
      </div>
    </div>
  );
}

function FootBar() {
  return (
    <div className="auth-foot">
      <span style={{ color: 'var(--fg-disabled)' }}>©</span>
      <span>Forge Utah Foundation</span>
      <span className="sep">·</span>
      <a href="#"><svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.1.79-.25.79-.56v-1.97c-3.2.7-3.87-1.54-3.87-1.54-.52-1.33-1.28-1.68-1.28-1.68-1.05-.71.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.76 2.7 1.25 3.36.96.1-.75.4-1.25.73-1.54-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.19-3.1-.12-.29-.51-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11 11 0 0 1 5.79 0c2.21-1.49 3.18-1.18 3.18-1.18.62 1.59.23 2.76.12 3.05.74.81 1.18 1.84 1.18 3.1 0 4.42-2.69 5.4-5.25 5.68.41.36.78 1.05.78 2.12v3.14c0 .31.21.67.8.56C20.21 21.39 23.5 17.08 23.5 12 23.5 5.65 18.35.5 12 .5z"/></svg> github</a>
      <span className="sep">·</span>
      <a href="#">status</a>
      <span className="sep">·</span>
      <a href="#">privacy</a>
      <div className="right">
        <span style={{ color: 'var(--fg-dim)' }}>need help?</span>{' '}
        <a href="#" style={{ marginLeft: 6 }}>#forge-auth on Slack →</a>
      </div>
    </div>
  );
}

Object.assign(window, { VariantCard, VariantTerminal, VariantSplit, TopBar, FootBar });
