/* global React, StateContent, ForgeMark */
/* eslint-disable no-unused-vars */

// =====================================================================
// Forge Auth Proxy — card variant
//
// This is the only layout variant shipped in production. The terminal,
// split, and tweaks-panel variants from the design scaffold are removed
// from the embedded asset tree (see U7 plan section).
//
// The card consumes: { flow, host, withAscii }. Only flow.state in
// {logged-out, error, unauthorized} is reachable at runtime — the server
// owns the connecting/success transitions via redirects.
// =====================================================================

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
              {flow.state === 'error' ? <>Something blew up</> :
               flow.state === 'unauthorized' ? <>Almost there</> :
               <>Sign in to continue<span className="cursor" /></>}
            </h1>
            <p className="lede">
              {flow.state === 'logged-out' && (
                host
                  ? <>Forge Auth is the proxy in front of our apps. Sign in with Slack — we'll forward you to <code style={{ color: 'var(--term-cyan)', background: 'transparent', fontFamily: 'var(--font-mono)' }}>{host}</code>.</>
                  : <>Forge Auth is the proxy in front of our apps. Sign in with Slack to access Forge Utah tools.</>
              )}
              {flow.state === 'error' && <>The Slack OAuth handshake didn't complete. Your session wasn't touched.</>}
              {flow.state === 'unauthorized' && <>You're signed into Slack, but not into the Forge Utah workspace. Switch to <code style={{ color: 'var(--term-cyan)', background: 'transparent', fontFamily: 'var(--font-mono)' }}>forgeutah.slack.com</code> and retry.</>}
            </p>
          </div>

          <StateContent flow={flow} host={host} withAscii={withAscii} layout="card" />
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

// =====================================================================
// Forge Auth Proxy — portal variant
//
// Rendered when /auth/me returns signed_in=true and there's no error
// query param. Shows the user's identity + a list of configured
// upstream apps + a sign-out form (POST /auth/logout, same-origin so
// the server's Origin check passes without a CSRF token).
// =====================================================================
function VariantPortal({ me }) {
  const apps = me.apps || [];
  return (
    <div className="auth-stage">
      <div className="auth-dotgrid" />
      <div className="auth-glow" />
      <TopBar />
      <div className="auth-main">
        <div className="va-card">
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
            <div className="logo-row">
              <ForgeMark size={32} />
              <div>
                <div className="text">forge<span className="accent">/</span>auth</div>
                <span className="sub">signed in</span>
              </div>
            </div>
            <span className="pill idle"><span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--term-green)', boxShadow: '0 0 6px var(--term-green)' }} /> session live</span>
          </div>

          <div>
            <span className="eyebrow">welcome</span>
            <h1 style={{ marginTop: 8 }}>{me.name || 'Forge member'}</h1>
            <p className="lede">
              {me.email
                ? <>You're signed in as <code style={{ color: 'var(--term-cyan)', background: 'transparent', fontFamily: 'var(--font-mono)' }}>{me.email}</code>. Pick an app below or open one in a new tab.</>
                : <>You're signed in. Pick an app below or open one in a new tab.</>}
            </p>
          </div>

          {apps.length > 0 ? (
            <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {apps.map(app => (
                <li key={app.host}>
                  <a href={app.url} className="btn-ghost" style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    padding: '12px 14px', textDecoration: 'none',
                  }}>
                    <span style={{ fontFamily: 'var(--font-mono)' }}>{app.host}</span>
                    <span style={{ color: 'var(--fg-dim)', fontSize: 12 }}>open →</span>
                  </a>
                </li>
              ))}
            </ul>
          ) : (
            <p style={{ color: 'var(--fg-dim)', fontSize: 13, margin: 0 }}>
              No apps are configured on this proxy yet.
            </p>
          )}

          <form method="POST" action="/auth/logout" style={{ marginTop: 8 }}>
            <button type="submit" className="btn-ghost" style={{ padding: '10px 14px', fontSize: 12 }}>
              Sign out
            </button>
          </form>
        </div>
      </div>
      <FootBar />
    </div>
  );
}

Object.assign(window, { VariantCard, VariantPortal, TopBar, FootBar });
