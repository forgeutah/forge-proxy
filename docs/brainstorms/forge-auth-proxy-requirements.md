---
date: 2026-05-19
topic: forge-auth-proxy
---

# Forge Auth Proxy

## Summary

A self-hosted reverse proxy that fronts all `*.forgeutah.tech` apps, authenticates users via Slack, and forwards identity and role metadata to upstream apps as plain HTTP headers. Single binary, SQLite-backed, branded login page, silent SSO across subdomains.

---

## Problem Frame

Forge Utah Foundation runs a small but growing portfolio of internal apps for its Utah engineering community — Deuce (volunteer time tracking), Platform (member dashboard), and more to come. Today these apps are live but unauthenticated: anyone who knows the URL can reach them. Each app would otherwise need to invent its own auth, its own login UI, its own user table, and its own answer to "is this person actually a member of Forge Utah?" — duplicated work that none of the small set of community contributors should have to repeat.

The community already gathers in one place: `forge-utah.slack.com`. That Slack workspace is the de facto source of truth for "is this person part of Forge Utah." Slack OAuth is the natural sign-in mechanism, and a shared proxy at the edge of `*.forgeutah.tech` is the natural place to enforce it once for every app.

The cost of not doing this is concrete: every new Forge app delays itself solving the same auth problem, and any open app published before the proxy exists is one URL leak away from being misused.

---

## Actors

- A1. **Forge Utah Slack member** — the primary end user. Signs into a Forge app via Slack and expects to be silently signed in to every other Forge app for the duration of their session.
- A2. **Forge Utah admin** — a trusted operator (initially the project owner) who manages elevated roles by editing the proxy's SQLite database directly.
- A3. **Upstream Forge app** — Deuce, Platform, and future apps. Receives requests only via the proxy; trusts identity headers because the network path is trusted.
- A4. **Slack workspace** — `forge-utah.slack.com`. The identity provider and the source of truth for baseline membership.

---

## Key Flows

- F1. **First-time sign-in (new member)**
  - **Trigger:** A Slack workspace member visits any `*.forgeutah.tech` app for the first time without a valid session.
  - **Actors:** A1, A4
  - **Steps:** Proxy detects no session → serves the branded login page → user clicks Continue with Slack → Slack OAuth round-trip → proxy verifies workspace membership → proxy auto-provisions a user record (no roles) → issues shared session cookie → redirects back to originally requested URL.
  - **Outcome:** User is signed in, exists in the proxy DB, has access to any app behind the proxy.
  - **Covered by:** R1, R2, R3, R4, R8, R12

- F2. **Returning sign-in / silent cross-app SSO**
  - **Trigger:** A signed-in user navigates from one Forge app to another (e.g. Deuce → Platform), or returns to an app after a previous visit.
  - **Actors:** A1, A3
  - **Steps:** Browser sends the shared `.forgeutah.tech` cookie → proxy validates session → injects identity and role headers → forwards request to upstream app.
  - **Outcome:** No visible login step. User lands on the destination app already authenticated.
  - **Covered by:** R5, R6, R7

- F3. **Unauthorized — signed in to Slack but not in workspace**
  - **Trigger:** A person authenticates with Slack but is not a member of `forge-utah.slack.com`.
  - **Actors:** A1, A4
  - **Steps:** OAuth completes → proxy queries Slack for workspace membership → membership absent → proxy shows a distinct branded "not in Forge Utah" message → no session cookie issued.
  - **Outcome:** Clear, branded denial. No partial state.
  - **Covered by:** R3, R13

- F4. **Sign-out**
  - **Trigger:** User clicks sign-out from any Forge app.
  - **Actors:** A1
  - **Steps:** App links to (or proxy intercepts) a sign-out endpoint → proxy invalidates the session record server-side → clears the shared `.forgeutah.tech` cookie → returns user to the branded login page.
  - **Outcome:** Single sign-out — user is signed out of every app behind the proxy.
  - **Covered by:** R7, R11

- F5. **Role change**
  - **Trigger:** Admin (A2) edits a user's roles directly in the SQLite database.
  - **Actors:** A2, A3
  - **Steps:** Admin edits DB → next time the user makes a request, the proxy reads the current roles and reflects them in the outbound headers.
  - **Outcome:** New roles take effect for that user on their next request, with no need to sign out and back in.
  - **Covered by:** R6, R10

---

## Requirements

**Authentication and access**
- R1. The proxy must serve a branded login page when an unauthenticated user reaches any `*.forgeutah.tech` host behind it.
- R2. "Continue with Slack" must be the only sign-in method exposed.
- R3. Sign-in must require active membership in the `forge-utah.slack.com` Slack workspace. Users who authenticate with Slack but are not workspace members must be shown a distinct branded message and denied a session.
- R4. On first successful sign-in, the proxy must auto-provision a user record with the user's stable identity (email, Slack user ID) and an empty roles list. No manual approval step.

**Session and SSO**
- R5. Sessions must be carried by a cookie scoped to `.forgeutah.tech` so a single sign-in covers every subdomain behind the proxy.
- R6. Identity and role data sent to upstream apps must reflect the current state of the proxy DB on each request, not a value frozen at sign-in time.
- R7. Sign-out must be a single action: invalidating the session must end the user's authenticated experience across every app behind the proxy.
- R8. Sessions must be revocable server-side — an admin must be able to terminate a session without rotating any global signing key.

**Header contract to upstream apps**
- R9. On every request forwarded to an upstream app, the proxy must inject headers carrying: the user's email, a stable user ID, the roles list, Slack profile basics (display name, avatar URL, Slack handle), and Slack workspace identity (Slack user ID and team ID).
- R10. Roles are passed as a flat list. The proxy must not enforce role-based access decisions — interpretation is left entirely to upstream apps.
- R11. Headers are plain values (no signed-JWT envelope). The trust model is the network path: upstream apps must only be reachable via the proxy, and must reject any request that bypasses it.

**Login page**
- R12. The login page must be branded as Forge Utah and visually consistent with the existing React scaffold in the repo. One of the three existing variants (card, terminal, split) is chosen for v1; the others may be retained as reference or deleted.
- R13. The login page must render all material UI states: signed-out, connecting, success, error, unauthorized (workspace member required), and already-signed-in.

**Operations**
- R14. User and role records must live in a single SQLite database file on a persistent volume, with a documented backup approach.
- R15. Role management in v1 is direct database edit only — there is no admin UI, Slack slash command, or web tool for managing roles.

---

## Acceptance Examples

- AE1. **Covers R3, R13.** Given a person who is signed into Slack but not a member of `forge-utah.slack.com`, when they click Continue with Slack, then the proxy completes the OAuth round-trip, sees no workspace membership, displays the unauthorized state on the branded login page, and does not issue a session cookie.
- AE2. **Covers R4, R5.** Given a brand-new Forge Utah Slack member with no record in the proxy DB, when they sign in for the first time, then a user row is created with their email, Slack ID, and an empty roles list, a `.forgeutah.tech`-scoped session cookie is set, and they are redirected to their originally requested URL.
- AE3. **Covers R5, R6.** Given a user already signed in at `deuce.forgeutah.tech`, when they navigate to `platform.forgeutah.tech`, then the proxy validates the existing cookie, looks up current roles, injects identity headers, and forwards the request without showing the login page.
- AE4. **Covers R6, R10.** Given a signed-in user whose roles are edited in the SQLite DB while their session is active, when they make their next request to any Forge app, then the proxy reflects the new roles in the headers sent to that app, without requiring re-authentication.
- AE5. **Covers R7.** Given a user signed in across Deuce and Platform, when they sign out from either app, then on their next visit to the other app they see the login page rather than being silently re-authenticated.
- AE6. **Covers R11.** Given an attacker who reaches an upstream app's origin directly without going through the proxy, when they send a request with forged identity headers, then the upstream app rejects the request because the network path is not the proxy.

---

## Success Criteria

- A Forge Utah Slack member can sign into any Forge app once and reach every Forge app without seeing the login page again until they sign out or their session expires.
- A new Forge app added behind the proxy needs zero custom auth code — only the ability to read identity headers and apply its own role interpretation.
- A non-member who finds an app URL cannot reach any Forge app's content, regardless of which subdomain they try.
- Onboarding a new Forge Utah Slack member is automatic on their first visit; no admin step is required for baseline access.
- The proxy can be operated by one person with periodic SQLite backups; no auth-tier ops work is expected month to month.

---

## Scope Boundaries

- Admin UI for managing roles (deferred — direct DB edits only in v1).
- Slack slash command for role management (deferred).
- Per-app role scoping (e.g., `deuce:admin`) — roles are a flat global list in v1; apps interpret.
- Service-to-service auth between Forge apps. The proxy mediates human browser traffic only.
- Detailed audit logging beyond what the session table naturally records.
- Rate limiting and abuse protection as a focused feature area — basic only, not a v1 emphasis.
- Additional identity providers (GitHub, Google, magic-link, etc.) — Slack is the only sign-in method.
- Signed JWT or any cryptographic envelope on the header payload to upstream apps — trust is network-path-based.
- Mobile SDKs or native-app sign-in flows — browser-only in v1.

---

## Key Decisions

- **Self-hosted reverse proxy, not edge function:** Chosen over Cloudflare Worker (the exe.dev reference model) and over a per-app SDK. Trades vendor portability over operational simplicity at Forge Utah's scale, keeps the language/runtime choice open for planning, and avoids both Cloudflare lock-in and per-language SDK proliferation.
- **SQLite over Postgres/D1:** A single user/role file fits Forge Utah's scale, has effectively zero ops cost, and survives full backups by copying one file. Postgres would add a database server to manage for no current benefit.
- **Single binary serving login page + proxy:** No separate static-host deploy for the login UI. One process to deploy, one place to wire OAuth, no CORS gymnastics between the auth UI and the proxy that backs it.
- **Hybrid access model:** Workspace membership grants baseline access; elevated roles are managed in the proxy DB. Avoids both the rigidity of an allowlist-only model and the flatness of a workspace-only model.
- **Roles as a flat list interpreted by apps:** The proxy stays an identity broker, not a permission system. Apps own their own authorization semantics.
- **Plain headers, no signed JWT:** Apps trust the network path. Avoids per-app verification code and key-distribution problems for a v1 with a small known set of upstream apps.
- **No role admin UI in v1:** Direct DB edits are acceptable because the role-managing audience is one person initially. Revisit when that breaks down.

---

## Dependencies / Assumptions

- A Slack app exists (or will be created) in the `forge-utah.slack.com` workspace with `users:read`, `users:read.email`, and the scopes necessary to verify workspace membership. Client ID and secret are configurable.
- Upstream Forge apps will be configured so their origins are reachable only via the proxy — either by living on a private network the proxy can reach, or by enforcing a shared secret on every request. The proxy guarantees identity headers; the network guarantees the trust path.
- DNS for `auth.forgeutah.tech` and each proxied app's hostname can be pointed at the proxy.
- The proxy host has a persistent volume for the SQLite file and a route to back it up off-host.
- An existing React scaffold for the login page is present in the repo (`auth-app.jsx`, `auth-core.jsx`, `auth-variants.jsx`, `styles/`) and will be carried into the proxy's static asset layout.

---

## Outstanding Questions

### Deferred to Planning

- [Affects R5, R8][Technical] Session storage shape — server-side session table in SQLite vs encrypted session cookie referencing a server record. Both meet R8; planning picks based on the chosen runtime.
- [Affects R14][Technical] Deployment target (Fly.io with a volume, a small VM with managed disk, etc.) and the corresponding backup mechanism (Litestream, snapshots, cron+rsync).
- [Affects R1, R9][Technical] Language/runtime for the proxy binary (Go, Node, Rust all viable). Planning weighs operator familiarity vs ecosystem fit for OAuth and reverse proxying.
- [Affects R9][Technical] Exact header naming convention (`X-Forge-*` vs `X-ForgeUtah-*` vs another scheme). Decision is small but should be locked once before apps start consuming headers.
- [Affects R3][Needs research] Whether Slack's OAuth flow surfaces workspace membership directly, or whether a follow-up `users.info`/`team.info` API call is required after the OAuth callback.
- [Affects R12] Which of the three React variants (card, terminal, split) ships as the v1 login page. Card is the conventional choice; terminal matches Forge's engineering brand identity. User decision.
