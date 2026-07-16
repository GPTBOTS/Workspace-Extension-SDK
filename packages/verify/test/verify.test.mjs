import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, createSign, generateKeyPairSync } from 'node:crypto';
import { verifyWsa, WsaVerificationError, exchangeWorkspaceCode } from '../src/index.ts';

const SECRET = 'test-secret-for-unit-tests';
const AUD = 'app.example.com';
const now = Math.floor(Date.now() / 1000);

const b64url = (buf) => Buffer.from(buf).toString('base64url');

function sign(payload, secret = SECRET, header = { alg: 'HS256', typ: 'JWT' }) {
  const h = b64url(JSON.stringify(header));
  const p = b64url(JSON.stringify(payload));
  const sig = createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url');
  return `${h}.${p}.${sig}`;
}

function basePayload(over = {}) {
  return {
    iss: 'gptbots-workspace',
    sub: 'acc-1',
    aud: AUD,
    role: 'OWNER',
    workspace_id: 'p-1',
    iat: now,
    exp: now + 300,
    username: 'Alice',
    email: 'a@x.com',
    ...over,
  };
}

function expectCode(fn, code) {
  try {
    fn();
    assert.fail('expected verifyWsa to throw');
  } catch (e) {
    assert.ok(e instanceof WsaVerificationError, `not a WsaVerificationError: ${e}`);
    assert.equal(e.code, code);
  }
}

test('verifies a valid HS256 token and maps all claims', () => {
  const id = verifyWsa(sign(basePayload()), { secret: SECRET, audience: AUD });
  assert.equal(id.accountId, 'acc-1');
  assert.equal(id.role, 'OWNER');
  assert.equal(id.workspaceId, 'p-1');
  assert.equal(id.username, 'Alice');
  assert.equal(id.email, 'a@x.com');
  assert.equal(id.issuedAt, now);
  assert.equal(id.expiresAt, now + 300);
});

test('normalizes an unknown role to MEMBER', () => {
  const id = verifyWsa(sign(basePayload({ role: 'viewer' })), { secret: SECRET, audience: AUD });
  assert.equal(id.role, 'MEMBER');
});

test('accepts array audience containing our host', () => {
  const id = verifyWsa(sign(basePayload({ aud: ['other.com', AUD] })), { secret: SECRET, audience: AUD });
  assert.equal(id.accountId, 'acc-1');
});

test('rejects a tampered signature', () => {
  const t = sign(basePayload());
  const tampered = `${t.slice(0, -2)}${t.endsWith('aa') ? 'bb' : 'aa'}`;
  expectCode(() => verifyWsa(tampered, { secret: SECRET, audience: AUD }), 'InvalidSignature');
});

test('rejects a wrong secret', () => {
  expectCode(() => verifyWsa(sign(basePayload()), { secret: 'other', audience: AUD }), 'InvalidSignature');
});

test('rejects an expired token beyond leeway', () => {
  expectCode(() => verifyWsa(sign(basePayload({ exp: now - 100 })), { secret: SECRET, audience: AUD }), 'Expired');
});

test('accepts an expired token within leeway', () => {
  const id = verifyWsa(sign(basePayload({ exp: now - 20 })), { secret: SECRET, audience: AUD, leewaySeconds: 30 });
  assert.equal(id.accountId, 'acc-1');
});

test('rejects a wrong audience', () => {
  expectCode(() => verifyWsa(sign(basePayload()), { secret: SECRET, audience: 'evil.example.com' }), 'WrongAudience');
});

test('rejects a wrong issuer', () => {
  expectCode(() => verifyWsa(sign(basePayload({ iss: 'nope' })), { secret: SECRET, audience: AUD }), 'WrongIssuer');
});

test('rejects a missing required claim (workspace_id)', () => {
  const p = basePayload();
  delete p.workspace_id;
  expectCode(() => verifyWsa(sign(p), { secret: SECRET, audience: AUD }), 'MissingClaim');
});

test('rejects an unsupported algorithm (alg=none)', () => {
  const t = sign(basePayload(), SECRET, { alg: 'none', typ: 'JWT' });
  expectCode(() => verifyWsa(t, { secret: SECRET, audience: AUD }), 'UnsupportedAlgorithm');
});

test('rejects a malformed token', () => {
  expectCode(() => verifyWsa('not-a-jwt', { secret: SECRET, audience: AUD }), 'InvalidToken');
});

test('a token signed with one app secret does NOT verify against a different secret (isolation)', () => {
  const appToken = sign(basePayload(), 'wext_appsecret');
  expectCode(() => verifyWsa(appToken, { secret: SECRET, audience: AUD }), 'InvalidSignature');
  // ...but verifies with its own secret:
  const id = verifyWsa(appToken, { secret: 'wext_appsecret', audience: AUD });
  assert.equal(id.accountId, 'acc-1');
});

// ── exp / iat / nbf enforcement (RFC 8725) ───────────────────────────────────────

test('rejects a token with NO exp claim (would otherwise never expire)', () => {
  const p = basePayload();
  delete p.exp;
  expectCode(() => verifyWsa(sign(p), { secret: SECRET, audience: AUD }), 'MissingClaim');
});

test('rejects a token whose exp is non-numeric (NaN/string never expires)', () => {
  expectCode(() => verifyWsa(sign(basePayload({ exp: 'soon' })), { secret: SECRET, audience: AUD }), 'MissingClaim');
});

test('rejects a token whose iat is far in the future', () => {
  const p = basePayload({ iat: now + 3600, exp: now + 3900 });
  expectCode(() => verifyWsa(sign(p), { secret: SECRET, audience: AUD }), 'NotYetValid');
});

test('rejects a token that is not yet valid (nbf in the future)', () => {
  const p = basePayload({ nbf: now + 3600 });
  expectCode(() => verifyWsa(sign(p), { secret: SECRET, audience: AUD }), 'NotYetValid');
});

test('accepts a token with no iat (iat is optional; only exp is mandatory)', () => {
  const p = basePayload();
  delete p.iat;
  const id = verifyWsa(sign(p), { secret: SECRET, audience: AUD });
  assert.equal(id.accountId, 'acc-1');
  assert.equal(id.issuedAt, undefined);
});

test('rejects a payload segment that is valid JSON but not an object', () => {
  // base64url("42") . base64url("null") . sig-shaped — must be InvalidToken, not a raw TypeError.
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64url('42');
  const sig = createHmac('sha256', SECRET).update(`${header}.${payload}`).digest('base64url');
  expectCode(() => verifyWsa(`${header}.${payload}.${sig}`, { secret: SECRET, audience: AUD }), 'InvalidToken');
});

// ── RS256 (roadmap) ──────────────────────────────────────────────────────────────

const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });

function signRs256(payload, header = { alg: 'RS256', typ: 'JWT' }) {
  const h = b64url(JSON.stringify(header));
  const p = b64url(JSON.stringify(payload));
  const signer = createSign('RSA-SHA256');
  signer.update(`${h}.${p}`);
  signer.end();
  const sig = signer.sign(rsa.privateKey).toString('base64url');
  return `${h}.${p}.${sig}`;
}

test('verifies a valid RS256 token when RS256 is allowed', () => {
  const token = signRs256(basePayload());
  const id = verifyWsa(token, {
    publicKey: rsa.publicKey.export({ type: 'spki', format: 'pem' }),
    audience: AUD,
    algorithms: ['RS256'],
  });
  assert.equal(id.accountId, 'acc-1');
  assert.equal(id.role, 'OWNER');
});

test('rejects an RS256 token under the default (HS256-only) whitelist — alg confusion guard', () => {
  const token = signRs256(basePayload());
  expectCode(
    () => verifyWsa(token, { publicKey: rsa.publicKey.export({ type: 'spki', format: 'pem' }), audience: AUD }),
    'UnsupportedAlgorithm',
  );
});

test('rejects a tampered RS256 signature', () => {
  const token = signRs256(basePayload());
  const bad = `${token.slice(0, -2)}${token.endsWith('aa') ? 'bb' : 'aa'}`;
  expectCode(
    () => verifyWsa(bad, { publicKey: rsa.publicKey.export({ type: 'spki', format: 'pem' }), audience: AUD, algorithms: ['RS256'] }),
    'InvalidSignature',
  );
});

// ── M-Auth: exchangeWorkspaceCode ────────────────────────────────────────────────

test('exchangeWorkspaceCode POSTs code + verifier and returns the wsa from data', async () => {
  let seen;
  const fakeFetch = async (url, init) => {
    seen = { url, body: JSON.parse(init.body), method: init.method };
    return {
      ok: true,
      status: 200,
      json: async () => ({ code: 0, msg: 'OK', data: { wsa: 'THE_WSA', token_type: 'Bearer', expires_in: 300 } }),
    };
  };
  const res = await exchangeWorkspaceCode({
    tokenUrl: 'https://www.gptbots.ai/api/console/account/extension-app/token',
    code: 'CODE',
    codeVerifier: 'VERIFIER',
    fetch: fakeFetch,
  });
  assert.equal(res.wsa, 'THE_WSA');
  assert.equal(res.tokenType, 'Bearer');
  assert.equal(res.expiresIn, 300);
  assert.equal(seen.method, 'POST');
  assert.deepEqual(seen.body, { code: 'CODE', codeVerifier: 'VERIFIER' });
  // and the returned wsa flows straight into verifyWsa (contract continuity is the point)
});

test('exchangeWorkspaceCode throws on a non-zero business code', async () => {
  const fakeFetch = async () => ({ ok: true, status: 200, json: async () => ({ code: 403209, message: 'invalid_grant' }) });
  await assert.rejects(
    () => exchangeWorkspaceCode({ tokenUrl: 'https://g/token', code: 'c', codeVerifier: 'v', fetch: fakeFetch }),
    /403209 \(invalid_grant\)/,
  );
});

test('exchangeWorkspaceCode falls back to a legacy msg field on a non-zero business code', async () => {
  const fakeFetch = async () => ({ ok: true, status: 200, json: async () => ({ code: 403210, msg: 'invalid_verifier' }) });
  await assert.rejects(
    () => exchangeWorkspaceCode({ tokenUrl: 'https://g/token', code: 'c', codeVerifier: 'v', fetch: fakeFetch }),
    /403210 \(invalid_verifier\)/,
  );
});

test('exchangeWorkspaceCode throws on a non-ok HTTP response', async () => {
  const fakeFetch = async () => ({ ok: false, status: 500, json: async () => ({}) });
  await assert.rejects(
    () => exchangeWorkspaceCode({ tokenUrl: 'https://g/token', code: 'c', codeVerifier: 'v', fetch: fakeFetch }),
    /status 500/,
  );
});

test('exchangeWorkspaceCode throws when the response lacks a wsa', async () => {
  const fakeFetch = async () => ({ ok: true, status: 200, json: async () => ({ code: 0, data: {} }) });
  await assert.rejects(
    () => exchangeWorkspaceCode({ tokenUrl: 'https://g/token', code: 'c', codeVerifier: 'v', fetch: fakeFetch }),
    /did not contain a wsa/,
  );
});

test('exchangeWorkspaceCode surfaces the business message on a non-ok response', async () => {
  const fakeFetch = async () => ({ ok: false, status: 403, json: async () => ({ code: 403209, message: 'invalid_grant' }) });
  await assert.rejects(
    () => exchangeWorkspaceCode({ tokenUrl: 'https://g/token', code: 'c', codeVerifier: 'v', fetch: fakeFetch }),
    /status 403 \(invalid_grant\)/,
  );
});

test('exchangeWorkspaceCode throws a clear error on invalid JSON', async () => {
  const fakeFetch = async () => ({ ok: true, status: 200, json: async () => { throw new SyntaxError('bad'); } });
  await assert.rejects(
    () => exchangeWorkspaceCode({ tokenUrl: 'https://g/token', code: 'c', codeVerifier: 'v', fetch: fakeFetch }),
    /invalid JSON/,
  );
});

test('exchangeWorkspaceCode rejects missing required args with TypeError', async () => {
  await assert.rejects(() => exchangeWorkspaceCode({ code: 'c', codeVerifier: 'v' }), TypeError);
  await assert.rejects(
    () => exchangeWorkspaceCode({ tokenUrl: 'https://g/token', codeVerifier: 'v' }),
    TypeError,
  );
});

test('exchangeWorkspaceCode aborts and reports a timeout when the endpoint hangs', async () => {
  // fetch that never resolves on its own — it only settles when the injected signal aborts.
  const hangingFetch = (url, init) =>
    new Promise((_resolve, reject) => {
      init.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    });
  await assert.rejects(
    () =>
      exchangeWorkspaceCode({
        tokenUrl: 'https://g/token',
        code: 'c',
        codeVerifier: 'v',
        fetch: hangingFetch,
        timeoutMs: 20,
      }),
    /timed out after 20ms/,
  );
});
