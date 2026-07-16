# @gptbots/workspace-extension-verify

Backend verification of the GPTBots Workspace login-handoff (`wsa`) token. **Zero runtime
dependencies** — uses Node's built-in `crypto`. Framework-agnostic (Express / NestJS / Koa /
anything).

```bash
npm i @gptbots/workspace-extension-verify
```

## API

### `verifyWsa(token, options): WorkspaceIdentity`

Verifies the token and returns the workspace user identity. Verification order:
**signature → issuer → audience → expiry (±leeway) → required claims**.

`exp` is **mandatory** (RFC 8725): a token with no finite `exp` is rejected as `MissingClaim`
rather than treated as valid forever. When present, `iat`/`nbf` must not be in the future beyond
`leewaySeconds` (a signature set far ahead would otherwise stay usable long past the intended
~300s window) — a future `iat`/`nbf` throws `NotYetValid`.

```ts
interface VerifyOptions {
  secret?: string;        // HS256 secret — your app's own secret. Required for HS256.
  publicKey?: string;     // RS256 PEM public key. Required for RS256 (roadmap).
  audience: string;       // YOUR app host — must equal the token `aud`.
  issuer?: string;        // default 'gptbots-workspace'
  leewaySeconds?: number; // default 30
  algorithms?: ('HS256' | 'RS256')[]; // default ['HS256']
}

interface WorkspaceIdentity {
  accountId: string;
  role: 'OWNER' | 'ADMIN' | 'MEMBER';
  workspaceId: string;
  username?: string; email?: string; avatar?: string; appName?: string;
  issuedAt?: number; expiresAt?: number;
}
```

Throws `WsaVerificationError` with a typed `.code`:
`InvalidToken | InvalidSignature | Expired | NotYetValid | WrongIssuer | WrongAudience | MissingClaim | UnsupportedAlgorithm`.
Throws `TypeError` on caller misconfiguration (e.g. missing key material).

## Example — Express middleware

```ts
import { verifyWsa, WsaVerificationError } from '@gptbots/workspace-extension-verify';

export function requireWorkspaceIdentity(secret: string, audience: string) {
  return (req, res, next) => {
    try {
      req.identity = verifyWsa(req.body.wsa, { secret, audience });
      next();
    } catch (e) {
      const code = e instanceof WsaVerificationError ? e.code : 'Error';
      res.status(401).json({ code });
    }
  };
}
```

## `exchangeWorkspaceCode(options)` — pull flow ("Login with GPTBots Workspace")

For the app-initiated login (a "Login with GPTBots Workspace" button, OAuth2 authorization-code +
PKCE): the browser SDK (`@gptbots/workspace-extension-sdk`) sends your backend a one-time `code`
plus the PKCE `codeVerifier`. Trade them for a `wsa` **from your backend** — never the browser:

```ts
import { exchangeWorkspaceCode, verifyWsa } from '@gptbots/workspace-extension-verify';

// POST /session/workspace-login  { code, codeVerifier }  (from completeWorkspaceLogin on the client)
app.post('/session/workspace-login', async (req, res) => {
  const { wsa } = await exchangeWorkspaceCode({
    tokenUrl: 'https://www.gptbots.ai/api/console/account/extension-app/token',
    code: req.body.code,
    codeVerifier: req.body.codeVerifier,
  });
  const identity = verifyWsa(wsa, { secret: MY_APP_SECRET, audience: 'app.example.com' });
  // establish your session from `identity`...
  res.json(identity);
});
```

`exchangeWorkspaceCode` throws on transport failure, a non-2xx response, a non-zero business
`code` (e.g. `403209 invalid_grant`, `403210 invalid_verifier`), or a response missing `data.wsa`.
The returned `wsa` is the **same** JWT the push flow hands off, so `verifyWsa` is unchanged.

The request is bounded by `timeoutMs` (default `10000`; pass `0` to disable) so a slow/hung
platform endpoint cannot pin your backend request indefinitely — a timeout throws
`token exchange timed out after <ms>ms`.

## Notes

- **HS256 today** — your app's own secret, issued once when the extension is registered.
- **RS256 is on the roadmap** — pass `{ publicKey, algorithms: ['RS256'] }` once GPTBots
  distributes public keys.
- Claims and defaults match the GPTBots Workspace platform signer:
  `iss=gptbots-workspace`, `aud=<app host>`, TTL ~300s.
