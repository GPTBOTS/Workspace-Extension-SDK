/**
 * @gptbots/workspace-extension-verify
 *
 * Framework-agnostic backend verification of the GPTBots Workspace login-handoff
 * token (`wsa`). Zero runtime dependencies — uses Node's built-in `crypto`.
 *
 * The token contract mirrors the GPTBots Workspace platform signer: a short-lived JWT
 *   { iss=gptbots-workspace, sub=accountId, aud=<app host>, role, workspace_id, iat, exp,
 *     username?, email?, avatar?, app_name? }
 * signed HS256 with your app's own secret, issued once when the extension is registered for
 * the organization.
 */
import { createHmac, createVerify, timingSafeEqual } from 'node:crypto';

export type WorkspaceRole = 'OWNER' | 'ADMIN' | 'MEMBER';

export interface WorkspaceIdentity {
  accountId: string;
  role: WorkspaceRole;
  workspaceId: string;
  username?: string;
  email?: string;
  avatar?: string;
  appName?: string;
  /** JWT `iat` (seconds since epoch), if present. */
  issuedAt?: number;
  /** JWT `exp` (seconds since epoch), if present. */
  expiresAt?: number;
}

export type WsaAlgorithm = 'HS256' | 'RS256';

export interface VerifyOptions {
  /** HS256 secret — your app's own secret. Required when verifying HS256 tokens. */
  secret?: string;
  /** RS256 public key (PEM). Required when verifying RS256 tokens (roadmap). */
  publicKey?: string;
  /** This application's host — must equal the token `aud`. */
  audience: string;
  /** Expected issuer. Defaults to `gptbots-workspace`. */
  issuer?: string;
  /** Clock-skew allowance for `exp`, in seconds. Defaults to 30. */
  leewaySeconds?: number;
  /** Accepted algorithms. Defaults to `['HS256']`. */
  algorithms?: WsaAlgorithm[];
}

export type WsaErrorCode =
  | 'InvalidToken'
  | 'InvalidSignature'
  | 'Expired'
  | 'NotYetValid'
  | 'WrongIssuer'
  | 'WrongAudience'
  | 'MissingClaim'
  | 'UnsupportedAlgorithm';

export class WsaVerificationError extends Error {
  readonly code: WsaErrorCode;
  constructor(code: WsaErrorCode, message: string) {
    super(message);
    this.name = 'WsaVerificationError';
    this.code = code;
  }
}

interface JwtHeader {
  alg?: string;
  typ?: string;
}

interface JwtPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  role?: string;
  workspace_id?: string;
  iat?: number;
  nbf?: number;
  exp?: number;
  username?: string;
  email?: string;
  avatar?: string;
  app_name?: string;
}

/**
 * Decode a base64url JWT segment to a JSON OBJECT. A segment that is valid JSON but not an object
 * (`"null"`, `"42"`, `"[]"`) is rejected here so callers can dot-access header/payload fields
 * without a raw `TypeError` leaking out — the caller's try/catch turns this into `InvalidToken`.
 */
function decodeSegment(seg: string): Record<string, unknown> {
  const json = Buffer.from(seg, 'base64url').toString('utf8');
  const parsed: unknown = JSON.parse(json);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new SyntaxError('JWT segment is not a JSON object');
  }
  return parsed as Record<string, unknown>;
}

function normalizeRole(raw: unknown): WorkspaceRole {
  const r = String(raw ?? '').toUpperCase();
  return r === 'OWNER' || r === 'ADMIN' ? r : 'MEMBER';
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Verify a `wsa` token and return the workspace user identity.
 *
 * Verification order: signature → issuer → audience → expiry (±leeway) → required claims.
 * Throws {@link WsaVerificationError} (with a typed `code`) on any verification failure;
 * throws `TypeError` on caller misconfiguration (e.g. missing key material).
 */
export function verifyWsa(token: string, options: VerifyOptions): WorkspaceIdentity {
  if (!options || typeof options.audience !== 'string' || options.audience.length === 0) {
    throw new TypeError('verifyWsa: options.audience is required');
  }
  if (typeof token !== 'string' || token.length === 0) {
    throw new WsaVerificationError('InvalidToken', 'Token is empty');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new WsaVerificationError('InvalidToken', 'Malformed JWT (expected 3 segments)');
  }
  const [headerSeg, payloadSeg, signatureSeg] = parts;

  let header: JwtHeader;
  let payload: JwtPayload;
  try {
    header = decodeSegment(headerSeg) as JwtHeader;
    payload = decodeSegment(payloadSeg) as JwtPayload;
  } catch {
    throw new WsaVerificationError('InvalidToken', 'Token header/payload is not valid base64url JSON');
  }

  const algorithms = options.algorithms ?? ['HS256'];
  const alg = header.alg as WsaAlgorithm | undefined;
  if (!alg || !algorithms.includes(alg)) {
    throw new WsaVerificationError('UnsupportedAlgorithm', `Algorithm not allowed: ${String(alg)}`);
  }

  const signingInput = `${headerSeg}.${payloadSeg}`;
  const signature = Buffer.from(signatureSeg, 'base64url');

  if (alg === 'HS256') {
    if (!options.secret) throw new TypeError('verifyWsa: options.secret is required for HS256');
    const expected = createHmac('sha256', options.secret).update(signingInput).digest();
    if (signature.length !== expected.length || !timingSafeEqual(signature, expected)) {
      throw new WsaVerificationError('InvalidSignature', 'HS256 signature mismatch');
    }
  } else {
    // RS256
    if (!options.publicKey) throw new TypeError('verifyWsa: options.publicKey is required for RS256');
    const verifier = createVerify('RSA-SHA256');
    verifier.update(signingInput);
    verifier.end();
    if (!verifier.verify(options.publicKey, signature)) {
      throw new WsaVerificationError('InvalidSignature', 'RS256 signature mismatch');
    }
  }

  const issuer = options.issuer ?? 'gptbots-workspace';
  if (payload.iss !== issuer) {
    throw new WsaVerificationError('WrongIssuer', `Unexpected issuer: ${String(payload.iss)}`);
  }

  const aud = payload.aud;
  const audOk = Array.isArray(aud) ? aud.includes(options.audience) : aud === options.audience;
  if (!audOk) {
    throw new WsaVerificationError('WrongAudience', `Token audience does not match ${options.audience}`);
  }

  const leeway = options.leewaySeconds ?? 30;
  const now = nowSeconds();

  // `exp` is MANDATORY (RFC 8725 §3.8): the platform always sets `exp = iat + 300`, and a wsa
  // without a finite `exp` would never expire. Treating an absent / NaN / non-finite `exp` as
  // "valid forever" is exactly the failure this rejects — a missing exp is a MissingClaim.
  if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) {
    throw new WsaVerificationError('MissingClaim', 'Missing or non-numeric claim: exp');
  }
  if (now > payload.exp + leeway) {
    throw new WsaVerificationError('Expired', 'Token has expired');
  }
  // `iat` / `nbf`, when present, must not sit in the future (beyond leeway). A signed token whose
  // issued-at / not-before is set far ahead would otherwise stay usable long past the intended
  // short window, defeating the point of the 300s `exp`. A non-numeric value is a malformed token.
  if (payload.iat !== undefined) {
    if (typeof payload.iat !== 'number' || !Number.isFinite(payload.iat)) {
      throw new WsaVerificationError('InvalidToken', 'Non-numeric claim: iat');
    }
    if (payload.iat > now + leeway) {
      throw new WsaVerificationError('NotYetValid', 'Token iat is in the future');
    }
  }
  if (payload.nbf !== undefined) {
    if (typeof payload.nbf !== 'number' || !Number.isFinite(payload.nbf)) {
      throw new WsaVerificationError('InvalidToken', 'Non-numeric claim: nbf');
    }
    if (now + leeway < payload.nbf) {
      throw new WsaVerificationError('NotYetValid', 'Token is not yet valid (nbf)');
    }
  }

  if (!payload.sub) throw new WsaVerificationError('MissingClaim', 'Missing claim: sub');
  if (!payload.role) throw new WsaVerificationError('MissingClaim', 'Missing claim: role');
  if (!payload.workspace_id) throw new WsaVerificationError('MissingClaim', 'Missing claim: workspace_id');

  return {
    accountId: payload.sub,
    role: normalizeRole(payload.role),
    workspaceId: payload.workspace_id,
    username: payload.username,
    email: payload.email,
    avatar: payload.avatar,
    appName: payload.app_name,
    issuedAt: payload.iat,
    expiresAt: payload.exp,
  };
}

// ── M-Auth: app-initiated "Login with GPTBots Workspace" ────────────────────────
//
// The pull flow (a "Login with GPTBots Workspace" button on the app) uses OAuth2
// authorization-code + PKCE. The browser only ever holds a short, opaque, one-time `code`;
// the app's BACKEND trades it — with the PKCE `code_verifier` — for the signed `wsa` here.
// The returned `wsa` is the exact same JWT the push flow hands off, so verify it with
// `verifyWsa` above. Runs on your backend; keeps every secret off the front channel.

export interface ExchangeWorkspaceCodeOptions {
  /**
   * The GPTBots token endpoint,
   * e.g. `https://www.gptbots.ai/api/console/account/extension-app/token`.
   */
  tokenUrl: string;
  /** The one-time authorization code from the redirect callback. */
  code: string;
  /** The PKCE `code_verifier` matching the `code_challenge` sent to `/authorize`. */
  codeVerifier: string;
  /** Injectable fetch (tests / older runtimes). Defaults to global `fetch`. */
  fetch?: typeof fetch;
  /**
   * Abort the request after this many milliseconds so a slow/hung platform endpoint cannot pin an
   * application-backend request indefinitely. Defaults to 10000. Pass `0` to disable the timeout.
   */
  timeoutMs?: number;
}

export interface WorkspaceCodeExchangeResult {
  /** The signed `wsa` JWT — verify it with {@link verifyWsa}. */
  wsa: string;
  /** Always `"Bearer"`. */
  tokenType?: string;
  /** wsa lifetime in seconds. */
  expiresIn?: number;
}

/**
 * Exchange a one-time authorization code + PKCE verifier for a signed `wsa`. Call this from
 * your BACKEND — never the browser (it authenticates by holding the verifier the browser
 * generated, and the wsa must not touch the front channel). Then hand the returned `wsa` to
 * {@link verifyWsa} to obtain the workspace identity.
 *
 * @throws Error on transport failure, a non-2xx response, a non-zero business `code`, or a
 *   response missing `data.wsa`.
 */
export async function exchangeWorkspaceCode(
  options: ExchangeWorkspaceCodeOptions,
): Promise<WorkspaceCodeExchangeResult> {
  if (!options || typeof options.tokenUrl !== 'string' || options.tokenUrl.length === 0) {
    throw new TypeError('exchangeWorkspaceCode: options.tokenUrl is required');
  }
  if (!options.code || !options.codeVerifier) {
    throw new TypeError('exchangeWorkspaceCode: code and codeVerifier are required');
  }
  const doFetch = options.fetch ?? (typeof fetch !== 'undefined' ? fetch : undefined);
  if (!doFetch) {
    throw new Error('exchangeWorkspaceCode: no fetch implementation available');
  }
  // Bound the whole exchange (connect + response body) so a hung platform endpoint cannot pin the
  // caller's request forever. AbortController is used directly (rather than AbortSignal.timeout) to
  // stay available on the older runtimes the injectable `fetch` targets; the timer is always cleared.
  const timeoutMs = options.timeoutMs ?? 10_000;
  const controller = timeoutMs > 0 ? new AbortController() : undefined;
  const timer =
    controller !== undefined ? setTimeout(() => controller.abort(), timeoutMs) : undefined;
  try {
    const resp = await doFetch(options.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: options.code, codeVerifier: options.codeVerifier }),
      signal: controller?.signal,
    });
    if (!resp.ok) {
      // Preserve the business reason (e.g. 403 { code: 403209, message: 'invalid_grant' }) so
      // PKCE/expired-code failures are diagnosable, not just an opaque HTTP status. The backend
      // serializes the field as `message` (CodeMsg.message); older payloads may use `msg`.
      const errBody = (await resp.json().catch(() => null)) as {
        code?: number;
        message?: string;
        msg?: string;
      } | null;
      const reasonText = errBody ? (errBody.message ?? errBody.msg) : undefined;
      const reason = typeof reasonText === 'string' ? ` (${reasonText})` : '';
      throw new Error(`exchangeWorkspaceCode: token exchange failed with status ${resp.status}${reason}`);
    }
    let body: {
      code?: number;
      message?: string;
      msg?: string;
      data?: { wsa?: string; token_type?: string; expires_in?: number };
    };
    try {
      body = (await resp.json()) as typeof body;
    } catch {
      throw new Error('exchangeWorkspaceCode: token endpoint returned an invalid JSON response');
    }
    if (typeof body.code === 'number' && body.code !== 0) {
      const reasonText = body.message ?? body.msg;
      throw new Error(`exchangeWorkspaceCode: token endpoint returned code ${body.code}${reasonText ? ` (${reasonText})` : ''}`);
    }
    const wsa = body.data?.wsa;
    if (!wsa) {
      throw new Error('exchangeWorkspaceCode: token response did not contain a wsa');
    }
    return { wsa, tokenType: body.data?.token_type, expiresIn: body.data?.expires_in };
  } catch (e) {
    if (controller?.signal.aborted) {
      throw new Error(`exchangeWorkspaceCode: token exchange timed out after ${timeoutMs}ms`);
    }
    throw e;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
