# @gptbots/workspace-extension-sdk

Zero-dependency browser helpers for the GPTBots Workspace login-handoff (`wsa`). No framework
required. The verification secret **never** lives here — the browser posts the token to *your*
backend, which verifies it with `@gptbots/workspace-extension-verify`.

```bash
npm i @gptbots/workspace-extension-sdk
```

## API

```ts
// Pure — reads ?wsa= from a query string (defaults to location.search).
readHandoffToken(search?: string, paramName?: string): string | null

// Removes ?wsa= from the URL via history.replaceState (keeps other params + hash). Safe no-op off-DOM.
stripHandoffToken(paramName?: string, ctx?: { history?: History; location?: Location }): void

// Convenience `use` flow: read wsa → POST to your backend → strip wsa → return identity.
// The token is stripped only AFTER a successful exchange, so a transient backend failure leaves
// `wsa` in the URL for a reload + retry (same philosophy as the pull flow's verifier retention).
// It is a one-time, ~300s token; if you would rather not have it survive a failed exchange, catch
// the rejection and call `stripHandoffToken()` yourself.
consumeHandoff(options: {
  exchangeUrl: string;     // YOUR backend endpoint that verifies the token
  fetch?: typeof fetch;    // injectable (tests / non-DOM)
  search?: string;         // defaults to location.search
  paramName?: string;      // defaults to 'wsa'
  strip?: boolean;         // defaults to true (applied only on success)
}): Promise<WorkspaceIdentity>
```

## Three tiers of consumption

```ts
// use — verify + session + role gating
const identity = await consumeHandoff({ exchangeUrl: '/session/exchange' });
if (identity.role === 'MEMBER') hideAdminUI();

// receive-only — read identity, keep your own auth (no session, no gating)
const token = readHandoffToken();
if (token) trackVisitor(token); // still send to your backend if you need the verified identity
stripHandoffToken();

// ignore — do nothing (equivalent to auth_mode=none)
```

## Pull flow — "Login with GPTBots Workspace" button (M-Auth)

Besides the push handoff above, an app can *initiate* login itself (OAuth2 authorization-code +
PKCE). The browser only ever holds a short one-time `code`; your backend swaps it for the `wsa`
(via `exchangeWorkspaceCode` in `@gptbots/workspace-extension-verify`).

```ts
// 1) On the "Login with GPTBots Workspace" button — generates PKCE, stores it, redirects.
await startWorkspaceLogin({
  authorizeUrl: 'https://www.gptbots.ai/api/console/account/extension-app/authorize',
  clientId: 'https://app.example.com/land',      // your registered app home URL
  redirectUri: 'https://app.example.com/callback', // must share your app's host
});

// 2) On your redirect_uri landing page — validates state (CSRF), exchanges via YOUR backend.
const identity = await completeWorkspaceLogin({ exchangeUrl: '/session/workspace-login' });
if (identity.role === 'MEMBER') hideAdminUI();
```

Lower-level building blocks if you don't want the `completeWorkspaceLogin` convenience:

```ts
startWorkspaceLogin(opts): Promise<{ url; state; codeVerifier }>  // opts.navigate=false → just build the URL
readAuthorizeCallback(search?, storage?): { code; state; codeVerifier } | null  // throws on CSRF state mismatch or ?error
stripAuthorizeCallback(ctx?)                                       // remove code/state from the URL
```

`readAuthorizeCallback` does **not** consume the stored request — consumption is deferred to a
**successful** `completeWorkspaceLogin`, so a transient exchange failure leaves the verifier in place
for a reload + retry.

`WorkspaceLoginError` carries a typed `.code`:
`NoCallback | MissingRequest | StateMismatch | NoFetch | ExchangeFailed | InvalidResponse | CryptoUnavailable | StorageUnavailable | InvalidAuthorizeUrl | AuthorizeError`.
State + the PKCE verifier are persisted in `sessionStorage` (override via `storage`). `startWorkspaceLogin`
throws `StorageUnavailable` (rather than silently navigating) when no persistent storage is resolvable,
and `InvalidAuthorizeUrl` for a relative/malformed `authorizeUrl`.

## Security

- **Always strip** the token from the URL after landing (`consumeHandoff` / `completeWorkspaceLogin`
  do this) so it never lingers in history / Referer.
- Treat `wsa` as a **one-time bootstrap** — exchange it for your own session; never re-send it.
- Pull flow: the `wsa` **never** touches the browser — only the opaque `code` does; the PKCE
  `codeVerifier` binds the code to the session that started the login.

## React

A `useWorkspaceIdentity()` convenience hook is planned as an optional subpath
(`@gptbots/workspace-extension-sdk/react`); the core stays framework-free. Until then, call
`consumeHandoff` in an effect and store the identity in your own state.
