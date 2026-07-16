# GPTBots Workspace Extension SDK

**English** | [简体中文](./README.zh-CN.md)

Build a **third-party extension app** that plugs into a GPTBots workspace. When a workspace
user opens your app from the **Workspace → Extensions** page, GPTBots hands off the user's
identity as a short-lived signed token (`?wsa=<JWT>`). This SDK turns that handshake into a
few framework-agnostic, install-and-use functions.

Two packages:

| Package | Runs in | Purpose |
|---|---|---|
| [`@gptbots/workspace-extension-verify`](./packages/verify) | your **backend** (Node) | Verify the `wsa` token → `WorkspaceIdentity`. Zero deps. |
| [`@gptbots/workspace-extension-sdk`](./packages/browser) | the **browser** | Read / strip / exchange the `wsa` token. Zero deps. |

> The verification **secret never lives in the browser**. The browser posts the token to *your*
> backend, which verifies it.

## Organization extension apps

Your app is an **organization extension**: an org OWNER/ADMIN registers it in
*Space Management → Extensions*. It is visible only to that organization and is signed with
**your app's own secret** (shown once at registration). Because the secret is unique to your
app, rotating or leaking it only affects your app.

You verify the handoff by calling `verifyWsa(token, { secret, audience })` with that secret.

## Consumption is optional

The platform hands off identity; whether you *use* it is your choice:

- **`use`** — verify (via your backend), establish a session, gate features by `role`.
- **`receive-only`** — read the identity for display/telemetry, but keep your own auth.
- **`ignore`** — never read it (equivalent to `auth_mode=none`; a plain external link).

`verifyWsa` and `readHandoffToken` are pure and side-effect-free, so "receive but don't use" is
free.

## Install

```bash
npm i @gptbots/workspace-extension-verify   # backend
npm i @gptbots/workspace-extension-sdk       # browser
```

## Backend — verify the token

```ts
import { verifyWsa, WsaVerificationError } from '@gptbots/workspace-extension-verify';

// POST /session/exchange  { wsa }
app.post('/session/exchange', (req, res) => {
  try {
    const identity = verifyWsa(req.body.wsa, {
      secret: process.env.EXTENSION_APP_SECRET,   // your app's secret (shown once at registration)
      audience: 'app.example.com',                 // YOUR app host — must equal the token `aud`
      // issuer: 'gptbots-workspace' (default), leewaySeconds: 30 (default), algorithms: ['HS256']
    });
    // identity = { accountId, role, workspaceId, username?, email?, avatar?, appName?, issuedAt?, expiresAt? }
    const session = createSession(identity);       // your own session
    res.cookie('sid', session, { httpOnly: true });
    res.json(identity);
  } catch (e) {
    const code = e instanceof WsaVerificationError ? e.code : 'Error';
    res.status(401).json({ code });
  }
});
```

## Browser — complete the handshake

```ts
import { consumeHandoff } from '@gptbots/workspace-extension-sdk';

// On your landing page:
const identity = await consumeHandoff({ exchangeUrl: '/session/exchange' });
// 1) reads ?wsa=  2) POSTs it to your backend (which verifies it)
// 3) strips ?wsa= from the URL  4) returns the identity
```

`receive-only` / `ignore` apps can call just `readHandoffToken()` or nothing at all.

## End-to-end flow

```
Workspace (Extensions page)                Your app
──────────────────────────                 ────────
click app ──POST /sign-token──▶ GPTBots
GPTBots signs a 5-min wsa JWT
open  https://app.example.com/?wsa=<JWT> ─▶ landing page
                                            consumeHandoff() ─POST /session/exchange {wsa}─▶ your backend
                                            your backend: verifyWsa() → identity → your session
                                            strip ?wsa= from URL
```

## Security notes

- **Secret only on the backend.** Never ship the verification secret to the browser.
- **Strip `wsa` immediately** (`consumeHandoff` does this) so it doesn't linger in history/Referer.
- **Short-lived** — the token TTL is ~5 minutes; treat it as a one-time bootstrap, then use your
  own session. Never re-send `wsa` on subsequent requests.
- **Your app's own secret** isolates blast radius to a single app/org. **Roadmap:** RS256
  public-key distribution (one app, one key) — `verifyWsa` already accepts `publicKey` +
  `algorithms: ['RS256']`.

## Develop

```bash
npm install
npm test          # node --test (zero external test deps)
npm run type-check # tsc --noEmit across packages
```

See also the authoritative GPTBots Workspace extension-app integration reference in the
official GPTBots documentation.
