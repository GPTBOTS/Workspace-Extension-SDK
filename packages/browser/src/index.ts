/**
 * @gptbots/workspace-extension-sdk
 *
 * Zero-dependency browser helpers for consuming the GPTBots Workspace login-handoff.
 *
 * Consumption is OPTIONAL — the platform hands off identity, but whether you use it is up
 * to you. Three modes:
 *   - `use`         — verify (via your backend) and establish a session / gate by role.
 *   - `receive-only`— read the identity but don't create a session; anonymous/own-auth flow.
 *   - `ignore`      — never read it (equivalent to `auth_mode=none`).
 *
 * All functions are pure/side-effect-free except `stripHandoffToken` (URL rewrite) and
 * `consumeHandoff` (network + strip). The verification secret NEVER lives in the browser —
 * `consumeHandoff` posts the token to YOUR backend, which verifies it with
 * `@gptbots/workspace-extension-verify`.
 */

export type WorkspaceRole = 'OWNER' | 'ADMIN' | 'MEMBER';

export interface WorkspaceIdentity {
  accountId: string;
  role: WorkspaceRole;
  workspaceId: string;
  username?: string;
  email?: string;
  avatar?: string;
  appName?: string;
  issuedAt?: number;
  expiresAt?: number;
}

const DEFAULT_PARAM = 'wsa';

function currentSearch(): string {
  return typeof location !== 'undefined' ? location.search : '';
}

/** Parse a query string (with or without a leading `?`) into URLSearchParams. */
function parseSearch(search: string): URLSearchParams {
  const q = search.startsWith('?') ? search.slice(1) : search;
  return new URLSearchParams(q);
}

/**
 * Read the raw handoff token from a query string. Pure — no side effects.
 * @param search a query string (with or without leading `?`); defaults to `location.search`.
 */
export function readHandoffToken(
  search: string = currentSearch(),
  paramName: string = DEFAULT_PARAM,
): string | null {
  return parseSearch(search).get(paramName);
}

export interface StripContext {
  history?: History;
  location?: Location;
}

/**
 * Remove the `wsa` param from the current URL via `history.replaceState` so it never lingers
 * in the address bar, browser history, or a leaked Referer. Safe no-op outside a browser.
 */
export function stripHandoffToken(paramName: string = DEFAULT_PARAM, ctx: StripContext = {}): void {
  const his = ctx.history ?? (typeof history !== 'undefined' ? history : undefined);
  const loc = ctx.location ?? (typeof location !== 'undefined' ? location : undefined);
  if (!his || !loc) return;
  const url = new URL(loc.href);
  if (!url.searchParams.has(paramName)) return;
  url.searchParams.delete(paramName);
  his.replaceState(his.state, '', `${url.pathname}${url.search}${url.hash}`);
}

export interface ConsumeHandoffOptions {
  /** Your OWN backend endpoint that verifies the token and returns the identity. */
  exchangeUrl: string;
  /** Injectable fetch (for tests / non-DOM runtimes). Defaults to global `fetch`. */
  fetch?: typeof fetch;
  /** Query string to read the token from. Defaults to `location.search`. */
  search?: string;
  /** Token query-param name. Defaults to `wsa`. */
  paramName?: string;
  /** Whether to strip the token from the URL after a successful exchange. Defaults to true. */
  strip?: boolean;
}

/**
 * Convenience flow for the `use` mode: read `wsa` → POST it to your backend `exchangeUrl`
 * (which verifies it) → strip it from the URL → return the identity your backend replied with.
 * This is sugar; `receive-only`/`ignore` apps can call only `readHandoffToken` or nothing.
 */
export async function consumeHandoff(options: ConsumeHandoffOptions): Promise<WorkspaceIdentity> {
  const paramName = options.paramName ?? DEFAULT_PARAM;
  const token = readHandoffToken(options.search, paramName);
  if (!token) {
    throw new Error('consumeHandoff: no handoff token present');
  }
  const doFetch = options.fetch ?? (typeof fetch !== 'undefined' ? fetch : undefined);
  if (!doFetch) {
    throw new Error('consumeHandoff: no fetch implementation available');
  }
  const resp = await doFetch(options.exchangeUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ wsa: token }),
    credentials: 'include',
  });
  if (!resp.ok) {
    throw new Error(`consumeHandoff: exchange failed with status ${resp.status}`);
  }
  let identity: WorkspaceIdentity;
  try {
    identity = (await resp.json()) as WorkspaceIdentity;
  } catch {
    throw new Error('consumeHandoff: exchange returned an invalid JSON response');
  }
  if (options.strip !== false) {
    stripHandoffToken(paramName);
  }
  return identity;
}

// ── M-Auth: app-initiated "Login with GPTBots Workspace" ────────────────────────
//
// The pull flow: the app renders a "Login with GPTBots Workspace" button. `startWorkspaceLogin`
// generates a PKCE pair, stashes the verifier + a CSRF `state`, and redirects the browser to the
// GPTBots authorize endpoint. After the user signs in and picks a workspace, GPTBots redirects
// back to your `redirect_uri?code&state`. `readAuthorizeCallback` validates `state`, returns the
// `code` + stored verifier; your BACKEND then exchanges them for a `wsa` (see
// `exchangeWorkspaceCode` in `@gptbots/workspace-extension-verify`). `completeWorkspaceLogin` is
// the `consumeHandoff`-style convenience that POSTs `{code, codeVerifier}` to YOUR backend.

/** Minimal `Storage`-shaped surface, so the flow is testable without a DOM. */
export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export type WorkspaceLoginErrorCode =
  | 'NoCallback'
  | 'MissingRequest'
  | 'StateMismatch'
  | 'NoFetch'
  | 'ExchangeFailed'
  | 'InvalidResponse'
  | 'CryptoUnavailable'
  | 'StorageUnavailable'
  | 'InvalidAuthorizeUrl'
  | 'AuthorizeError';

export class WorkspaceLoginError extends Error {
  readonly code: WorkspaceLoginErrorCode;
  constructor(code: WorkspaceLoginErrorCode, message: string) {
    super(message);
    this.name = 'WorkspaceLoginError';
    this.code = code;
  }
}

const LOGIN_STORAGE_KEY = 'gptbots:wext:login';

function defaultStorage(): StorageLike | undefined {
  try {
    return typeof sessionStorage !== 'undefined' ? sessionStorage : undefined;
  } catch {
    // Accessing sessionStorage can throw (e.g. sandboxed iframe).
    return undefined;
  }
}

function base64UrlEncode(bytes: Uint8Array): string {
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomString(byteLength = 32): string {
  const buf = new Uint8Array(byteLength);
  crypto.getRandomValues(buf);
  return base64UrlEncode(buf);
}

async function sha256Base64Url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return base64UrlEncode(new Uint8Array(digest));
}

export interface StartWorkspaceLoginOptions {
  /**
   * The GPTBots authorize endpoint (absolute),
   * e.g. `https://www.gptbots.ai/api/console/account/extension-app/authorize`.
   */
  authorizeUrl: string;
  /** Your registered app home URL (the `client_id`). */
  clientId: string;
  /** Where GPTBots redirects the code back to — must share the app's host. */
  redirectUri: string;
  /** CSRF `state`. Generated (16 random bytes) if omitted. */
  state?: string;
  /** Pre-select a workspace to skip the org-picker step. */
  workspaceId?: string;
  /** Where to stash the PKCE verifier + state. Defaults to `sessionStorage`. */
  storage?: StorageLike;
  /** How to navigate. Defaults to `location.assign`. */
  redirect?: (url: string) => void;
  /** Set false to only build the URL (popup flows / tests) and not navigate. */
  navigate?: boolean;
}

export interface WorkspaceLoginRequest {
  /** The fully built authorize URL. */
  url: string;
  /** The CSRF state persisted for this request. */
  state: string;
  /** The PKCE code_verifier persisted for this request. */
  codeVerifier: string;
}

/**
 * Begin the pull login: generate PKCE, persist the verifier + state, build the authorize URL,
 * and (unless `navigate: false`) redirect the browser to it. Returns the built request so popup
 * flows and tests can drive it manually.
 */
export async function startWorkspaceLogin(
  options: StartWorkspaceLoginOptions,
): Promise<WorkspaceLoginRequest> {
  // PKCE needs Web Crypto + btoa, which require a secure context (HTTPS/localhost). Fail with a
  // typed error instead of a raw ReferenceError so callers can handle it.
  if (typeof crypto === 'undefined' || !crypto.getRandomValues || !crypto.subtle || typeof btoa === 'undefined') {
    throw new WorkspaceLoginError(
      'CryptoUnavailable',
      'Web Crypto (crypto.subtle) is unavailable — a secure context (HTTPS or localhost) is required',
    );
  }
  // Empty string is not a valid CSRF state: `?? ` keeps '' (only null/undefined are replaced), which
  // would let a forged callback with an empty `state` pass the equality check. Generate one instead.
  const state = options.state && options.state.length > 0 ? options.state : randomString(16);
  const codeVerifier = randomString(32);
  const codeChallenge = await sha256Base64Url(codeVerifier);

  // Build (and validate) the authorize URL BEFORE persisting/navigating so a relative or malformed
  // URL surfaces as a typed error instead of a raw TypeError, and never strands stashed state.
  let url: URL;
  try {
    url = new URL(options.authorizeUrl);
  } catch {
    throw new WorkspaceLoginError(
      'InvalidAuthorizeUrl',
      `authorizeUrl must be an absolute URL, got: ${String(options.authorizeUrl)}`,
    );
  }

  // storage?.setItem is a silent no-op when storage is undefined; if we then navigate, the callback
  // page can never find the PKCE verifier. Fail loudly instead (unless a storage was injected).
  const storage = options.storage ?? defaultStorage();
  if (!storage) {
    throw new WorkspaceLoginError(
      'StorageUnavailable',
      'persistent storage (sessionStorage) is unavailable — the PKCE verifier cannot be stashed',
    );
  }
  storage.setItem(LOGIN_STORAGE_KEY, JSON.stringify({ state, codeVerifier }));

  url.searchParams.set('client_id', options.clientId);
  url.searchParams.set('redirect_uri', options.redirectUri);
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  if (options.workspaceId) url.searchParams.set('workspace_id', options.workspaceId);
  const built = url.toString();

  if (options.navigate !== false) {
    const redirect =
      options.redirect ?? (typeof location !== 'undefined' ? (u: string) => location.assign(u) : undefined);
    redirect?.(built);
  }
  return { url: built, state, codeVerifier };
}

export interface AuthorizeCallback {
  /** The one-time authorization code. */
  code: string;
  /** The `state` echoed back (already validated against the stored one). */
  state: string | null;
  /** The PKCE verifier to send — with the code — to your backend. */
  codeVerifier: string;
}

/**
 * On the `redirect_uri` landing page: read `code` + `state`, validate `state` against the stored
 * request (CSRF guard), and return the code + PKCE verifier. Does NOT consume the stored request —
 * consumption is deferred to a SUCCESSFUL exchange (see `completeWorkspaceLogin`) so a transient
 * exchange failure preserves the verifier for a reload + retry. Returns null when there is no
 * `code` (and no `error`) in the URL (not a callback navigation).
 *
 * @throws WorkspaceLoginError `StateMismatch` on CSRF mismatch, `MissingRequest` when no/corrupt
 *   login request is stored (start the flow first), `AuthorizeError` when the callback is an OAuth
 *   error redirect (`?error=...`).
 */
export function readAuthorizeCallback(
  search: string = currentSearch(),
  storage?: StorageLike,
): AuthorizeCallback | null {
  const params = parseSearch(search);
  const code = params.get('code');
  const state = params.get('state');

  // Forward-compat: an OAuth error redirect (`?error=access_denied&state=...`) is a real callback,
  // not "no callback". Validate state (same CSRF guard), clear the stored request, and surface it.
  const errorParam = params.get('error');
  if (!code && errorParam) {
    const store = storage ?? defaultStorage();
    const raw = store?.getItem(LOGIN_STORAGE_KEY) ?? null;
    let storedState: string | undefined;
    if (raw) {
      try {
        storedState = (JSON.parse(raw) as { state?: string }).state;
      } catch {
        storedState = undefined;
      }
    }
    if (!storedState || !state || storedState !== state) {
      throw new WorkspaceLoginError('StateMismatch', 'CSRF state mismatch — discarding the callback');
    }
    store?.removeItem(LOGIN_STORAGE_KEY);
    const description = params.get('error_description');
    throw new WorkspaceLoginError(
      'AuthorizeError',
      `Authorization failed: ${errorParam}${description ? ` (${description})` : ''}`,
    );
  }

  if (!code) return null;

  const store = storage ?? defaultStorage();
  const raw = store?.getItem(LOGIN_STORAGE_KEY) ?? null;
  if (!raw) {
    throw new WorkspaceLoginError('MissingRequest', 'No stored login request — call startWorkspaceLogin first');
  }
  let stored: { state?: string; codeVerifier?: string };
  try {
    stored = JSON.parse(raw);
  } catch {
    throw new WorkspaceLoginError('MissingRequest', 'Stored login request is corrupt');
  }
  if (!stored.codeVerifier) {
    throw new WorkspaceLoginError('MissingRequest', 'Stored login request is missing the PKCE verifier');
  }
  // Reject empty/absent state on either side: a missing stored state or a blank callback state must
  // never satisfy the CSRF check (belt-and-suspenders with the empty-state guard in startWorkspaceLogin).
  if (!stored.state || !state || stored.state !== state) {
    throw new WorkspaceLoginError('StateMismatch', 'CSRF state mismatch — discarding the callback');
  }
  // NOTE: the stored request is intentionally NOT removed here — completeWorkspaceLogin removes it
  // only after a successful exchange, so a transient failure can be retried on reload.
  return { code, state, codeVerifier: stored.codeVerifier };
}

/** Strip `code` and `state` from the current URL after a successful login. */
export function stripAuthorizeCallback(ctx: StripContext = {}): void {
  const his = ctx.history ?? (typeof history !== 'undefined' ? history : undefined);
  const loc = ctx.location ?? (typeof location !== 'undefined' ? location : undefined);
  if (!his || !loc) return;
  const url = new URL(loc.href);
  let changed = false;
  for (const p of ['code', 'state']) {
    if (url.searchParams.has(p)) {
      url.searchParams.delete(p);
      changed = true;
    }
  }
  if (changed) his.replaceState(his.state, '', `${url.pathname}${url.search}${url.hash}`);
}

export interface CompleteWorkspaceLoginOptions {
  /** YOUR backend endpoint that takes `{code, codeVerifier}` and returns the identity. */
  exchangeUrl: string;
  /** Injectable fetch (tests / non-DOM runtimes). Defaults to global `fetch`. */
  fetch?: typeof fetch;
  /** Query string to read the callback from. Defaults to `location.search`. */
  search?: string;
  /** Storage holding the login request. Defaults to `sessionStorage`. */
  storage?: StorageLike;
  /** Strip `code`/`state` from the URL after success. Defaults to true. */
  strip?: boolean;
}

/**
 * Convenience for the `use` mode: read + validate the callback → POST `{code, codeVerifier}` to
 * YOUR backend `exchangeUrl` (which calls `exchangeWorkspaceCode` + `verifyWsa`) → strip the URL
 * → return the identity your backend replied with.
 */
export async function completeWorkspaceLogin(
  options: CompleteWorkspaceLoginOptions,
): Promise<WorkspaceIdentity> {
  const cb = readAuthorizeCallback(options.search, options.storage);
  if (!cb) {
    throw new WorkspaceLoginError('NoCallback', 'No authorization code present in the URL');
  }
  const doFetch = options.fetch ?? (typeof fetch !== 'undefined' ? fetch : undefined);
  if (!doFetch) {
    throw new WorkspaceLoginError('NoFetch', 'no fetch implementation available');
  }
  const resp = await doFetch(options.exchangeUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: cb.code, codeVerifier: cb.codeVerifier }),
    credentials: 'include',
  });
  if (!resp.ok) {
    throw new WorkspaceLoginError('ExchangeFailed', `exchange failed with status ${resp.status}`);
  }
  let identity: WorkspaceIdentity;
  try {
    identity = (await resp.json()) as WorkspaceIdentity;
  } catch {
    throw new WorkspaceLoginError('InvalidResponse', 'exchange returned an invalid JSON response');
  }
  // The exchange definitively succeeded: only now consume the stored login request (readAuthorizeCallback
  // deliberately left it in place) so a transient failure above preserves the verifier for a reload + retry.
  const store = options.storage ?? defaultStorage();
  store?.removeItem(LOGIN_STORAGE_KEY);
  if (options.strip !== false) {
    stripAuthorizeCallback();
  }
  return identity;
}
