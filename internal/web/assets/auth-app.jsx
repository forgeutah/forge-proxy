/* global React, ReactDOM, VariantCard */
/* eslint-disable no-unused-vars */

// =====================================================================
// Forge Auth Proxy — root app
//
// The server owns the OAuth round-trip: `connecting` / `success` /
// `logged-in` states from the design scaffold are never user-visible in
// production. This file therefore renders only the three terminal states
// the server can land us on:
//
//   ?error=auth_failed       → error card
//   ?error=not_in_workspace  → unauthorized card
//   (none)                   → logged-out card
//
// The "Continue with Slack" button is a plain link to /auth/login so the
// flow works without JS and stays server-driven. The optional return_to
// query param on this page is preserved into the login link so upstream
// apps can carry the redirect target through.
// =====================================================================

const DEFAULT_HOST = 'deuce.forgeutah.tech';

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

// Build a /auth/login href that preserves any incoming return_to so the
// server's strict validator can decide what to do with it. We deliberately
// do not validate here — the server is the trust boundary.
function loginHref(returnTo) {
  if (!returnTo) return '/auth/login';
  return '/auth/login?return_to=' + encodeURIComponent(returnTo);
}

function AuthApp() {
  const state = readErrorState();
  const returnTo = readReturnTo();
  // The card variant displays a destination host string; if we have a
  // return_to, surface its host. Otherwise fall back to a generic name.
  let displayHost = DEFAULT_HOST;
  if (returnTo) {
    try {
      displayHost = new URL(returnTo).host || DEFAULT_HOST;
    } catch (_) {
      displayHost = DEFAULT_HOST;
    }
  }

  // The card variant expects a `flow` object with `state` and a
  // `startConnecting()` action for the Slack button + retry buttons. In
  // production every "start" action is a navigation to /auth/login so the
  // server can run the real OAuth round-trip — the React app never owns
  // the connecting state itself.
  const startConnecting = React.useCallback(() => {
    window.location.assign(loginHref(returnTo));
  }, [returnTo]);

  const flow = {
    state,
    stepIdx: -1,
    countdown: 0,
    startConnecting,
  };

  return <VariantCard flow={flow} host={displayHost} withAscii={true} />;
}

ReactDOM.createRoot(document.getElementById('root')).render(<AuthApp />);
