/* global React, ReactDOM, VariantCard, VariantPortal */
/* eslint-disable no-unused-vars */

// =====================================================================
// Forge Auth Proxy — root app
//
// On mount we fetch /auth/me to learn whether the caller has a live
// session. Two terminal renders:
//
//   signed_in=false  → sign-in card (Slack button + error/unauthorized states)
//   signed_in=true   → portal (apps list + sign-out)
//
// The server owns the OAuth round-trip, so the design-scaffold
// `connecting` / `success` mid-flow states never render in production.
// The "Continue with Slack" button is a plain link to /auth/login so
// the flow works without JS and stays server-driven; any return_to
// query param on this page is preserved into the login link.
// =====================================================================

function readErrorState() {
  const params = new URLSearchParams(window.location.search);
  const err = params.get('error');
  if (err === 'auth_failed') return 'error';
  if (err === 'not_in_workspace') return 'unauthorized';
  return 'logged-out';
}

function readReturnTo() {
  const params = new URLSearchParams(window.location.search);
  return params.get('return_to') || '';
}

function loginHref(returnTo) {
  if (!returnTo) return '/auth/login';
  return '/auth/login?return_to=' + encodeURIComponent(returnTo);
}

// useMe fetches /auth/me once on mount. Returns { loaded, me } where
// `me` is null until the fetch resolves. We treat any fetch failure as
// "signed out" — same fail-open posture the server uses — so a flaky
// network never blocks the sign-in card from rendering.
function useMe() {
  const [me, setMe] = React.useState(null);
  const [loaded, setLoaded] = React.useState(false);
  React.useEffect(() => {
    let cancelled = false;
    fetch('/auth/me', { credentials: 'same-origin', cache: 'no-store' })
      .then(r => (r.ok ? r.json() : { signed_in: false }))
      .catch(() => ({ signed_in: false }))
      .then(data => {
        if (!cancelled) {
          setMe(data);
          setLoaded(true);
        }
      });
    return () => { cancelled = true; };
  }, []);
  return { loaded, me };
}

function AuthApp() {
  const { loaded, me } = useMe();
  const errorState = readErrorState();
  const returnTo = readReturnTo();

  // Show the destination host only when we actually have one (via
  // return_to). No hardcoded fallback — stale app names outlive the
  // apps they reference.
  let displayHost = '';
  if (returnTo) {
    try {
      displayHost = new URL(returnTo).host || '';
    } catch (_) {
      displayHost = '';
    }
  }

  const startConnecting = React.useCallback(() => {
    window.location.assign(loginHref(returnTo));
  }, [returnTo]);

  // Pre-fetch render: keep the slot empty so we don't flash the
  // sign-in card and then swap to the portal a few ms later. The fetch
  // is local and fast — the blank moment is barely perceptible.
  if (!loaded) return null;

  // Signed-in and no error to surface → portal.
  if (me && me.signed_in && errorState === 'logged-out') {
    return <VariantPortal me={me} />;
  }

  // Signed-out (or signed-in with an explicit error query) → card.
  const flow = {
    state: errorState,
    stepIdx: -1,
    countdown: 0,
    startConnecting,
  };
  return <VariantCard flow={flow} host={displayHost} withAscii={true} build={me ? me.build : null} />;
}

ReactDOM.createRoot(document.getElementById('root')).render(<AuthApp />);
