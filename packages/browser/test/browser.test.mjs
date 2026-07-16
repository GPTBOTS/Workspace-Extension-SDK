import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  readHandoffToken,
  stripHandoffToken,
  consumeHandoff,
  startWorkspaceLogin,
  readAuthorizeCallback,
  completeWorkspaceLogin,
  WorkspaceLoginError,
} from '../src/index.ts';

function memStorage(seed) {
  const m = new Map(Object.entries(seed ?? {}));
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, v),
    removeItem: (k) => m.delete(k),
    _map: m,
  };
}

const s256 = (v) => createHash('sha256').update(v).digest('base64url');

test('readHandoffToken parses the wsa param (pure, no side effects)', () => {
  assert.equal(readHandoffToken('?wsa=abc.def.ghi'), 'abc.def.ghi');
  assert.equal(readHandoffToken('wsa=xyz'), 'xyz');
  assert.equal(readHandoffToken('?foo=1&wsa=zzz'), 'zzz');
  assert.equal(readHandoffToken('?foo=1'), null);
  assert.equal(readHandoffToken(''), null);
});

test('stripHandoffToken removes wsa via injected history/location, keeping other params + hash', () => {
  const calls = [];
  const fakeLocation = { href: 'https://app.example.com/land?wsa=tok&keep=1#frag' };
  const fakeHistory = { state: { a: 1 }, replaceState: (_s, _t, url) => calls.push(url) };
  stripHandoffToken('wsa', { history: fakeHistory, location: fakeLocation });
  assert.equal(calls.length, 1);
  assert.ok(!calls[0].includes('wsa='), `wsa not stripped: ${calls[0]}`);
  assert.ok(calls[0].includes('keep=1'));
  assert.ok(calls[0].includes('#frag'));
});

test('stripHandoffToken is a no-op when the param is absent', () => {
  let called = false;
  stripHandoffToken('wsa', {
    history: { state: null, replaceState: () => { called = true; } },
    location: { href: 'https://x.com/a?b=1' },
  });
  assert.equal(called, false);
});

test('consumeHandoff posts the token to the exchange endpoint and returns the identity', async () => {
  let seen;
  const fakeFetch = async (url, init) => {
    seen = { url, body: init.body, method: init.method };
    return { ok: true, status: 200, json: async () => ({ accountId: 'acc-9', role: 'MEMBER', workspaceId: 'p-2' }) };
  };
  const id = await consumeHandoff({
    exchangeUrl: '/session/exchange',
    fetch: fakeFetch,
    search: '?wsa=THE_TOKEN',
    strip: false,
  });
  assert.equal(id.accountId, 'acc-9');
  assert.equal(seen.url, '/session/exchange');
  assert.equal(seen.method, 'POST');
  assert.equal(seen.body, JSON.stringify({ wsa: 'THE_TOKEN' }));
});

test('consumeHandoff throws when no token is present', async () => {
  await assert.rejects(() =>
    consumeHandoff({ exchangeUrl: '/x', fetch: async () => ({ ok: true, json: async () => ({}) }), search: '?foo=1' }),
  );
});

test('consumeHandoff throws on a non-ok exchange response', async () => {
  const fakeFetch = async () => ({ ok: false, status: 401, json: async () => ({}) });
  await assert.rejects(() =>
    consumeHandoff({ exchangeUrl: '/x', fetch: fakeFetch, search: '?wsa=t', strip: false }),
  );
});

test('consumeHandoff throws a clear error on an invalid JSON exchange response', async () => {
  const fakeFetch = async () => ({
    ok: true,
    status: 200,
    json: async () => {
      throw new SyntaxError('Unexpected end of JSON input');
    },
  });
  await assert.rejects(
    () => consumeHandoff({ exchangeUrl: '/x', fetch: fakeFetch, search: '?wsa=t', strip: false }),
    /invalid JSON/,
  );
});

// ── M-Auth (pull flow) ──────────────────────────────────────────────────────────

test('startWorkspaceLogin builds a PKCE authorize URL and persists the verifier + state', async () => {
  const storage = memStorage();
  const req = await startWorkspaceLogin({
    authorizeUrl: 'https://www.gptbots.ai/api/console/account/extension-app/authorize',
    clientId: 'https://app.example.com/land',
    redirectUri: 'https://app.example.com/callback',
    state: 'st-123',
    storage,
    navigate: false,
  });

  const url = new URL(req.url);
  assert.equal(url.searchParams.get('client_id'), 'https://app.example.com/land');
  assert.equal(url.searchParams.get('redirect_uri'), 'https://app.example.com/callback');
  assert.equal(url.searchParams.get('state'), 'st-123');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  // the challenge must be S256(verifier)
  assert.equal(url.searchParams.get('code_challenge'), s256(req.codeVerifier));

  const stored = JSON.parse(storage.getItem('gptbots:wext:login'));
  assert.equal(stored.state, 'st-123');
  assert.equal(stored.codeVerifier, req.codeVerifier);
});

test('startWorkspaceLogin generates a random state when none is supplied and can carry workspace_id', async () => {
  const storage = memStorage();
  const req = await startWorkspaceLogin({
    authorizeUrl: 'https://g/authorize',
    clientId: 'https://app.example.com/land',
    redirectUri: 'https://app.example.com/callback',
    workspaceId: 'p-9',
    storage,
    navigate: false,
  });
  assert.ok(req.state.length > 0);
  assert.equal(new URL(req.url).searchParams.get('workspace_id'), 'p-9');
});

test('readAuthorizeCallback returns code + verifier when state matches, and does NOT consume the request', () => {
  const storage = memStorage({
    'gptbots:wext:login': JSON.stringify({ state: 'st-1', codeVerifier: 'verifier-abc' }),
  });
  const cb = readAuthorizeCallback('?code=THE_CODE&state=st-1', storage);
  assert.equal(cb.code, 'THE_CODE');
  assert.equal(cb.codeVerifier, 'verifier-abc');
  // consumption is deferred to a successful completeWorkspaceLogin — the request is still present
  assert.equal(storage.getItem('gptbots:wext:login'), JSON.stringify({ state: 'st-1', codeVerifier: 'verifier-abc' }));
});

test('readAuthorizeCallback throws StateMismatch on a forged state', () => {
  const storage = memStorage({
    'gptbots:wext:login': JSON.stringify({ state: 'st-real', codeVerifier: 'v' }),
  });
  try {
    readAuthorizeCallback('?code=c&state=st-evil', storage);
    assert.fail('expected a StateMismatch throw');
  } catch (e) {
    assert.ok(e instanceof WorkspaceLoginError);
    assert.equal(e.code, 'StateMismatch');
  }
});

test('readAuthorizeCallback returns null when there is no code (not a callback)', () => {
  const storage = memStorage({ 'gptbots:wext:login': JSON.stringify({ state: 's', codeVerifier: 'v' }) });
  assert.equal(readAuthorizeCallback('?foo=1', storage), null);
});

test('completeWorkspaceLogin posts {code, codeVerifier} to the app backend and returns the identity', async () => {
  const storage = memStorage({
    'gptbots:wext:login': JSON.stringify({ state: 'st-1', codeVerifier: 'verifier-abc' }),
  });
  let seen;
  const fakeFetch = async (url, init) => {
    seen = { url, body: init.body, method: init.method };
    return { ok: true, status: 200, json: async () => ({ accountId: 'acc-7', role: 'ADMIN', workspaceId: 'p-1' }) };
  };
  const id = await completeWorkspaceLogin({
    exchangeUrl: '/session/workspace-login',
    fetch: fakeFetch,
    search: '?code=THE_CODE&state=st-1',
    storage,
    strip: false,
  });
  assert.equal(id.accountId, 'acc-7');
  assert.equal(seen.method, 'POST');
  assert.equal(seen.body, JSON.stringify({ code: 'THE_CODE', codeVerifier: 'verifier-abc' }));
});

// ── M-Auth error branches (CSRF / storage / exchange failures) ────────────────────

test('startWorkspaceLogin replaces an empty-string state with a random one (CSRF hardening)', async () => {
  const storage = memStorage();
  const req = await startWorkspaceLogin({
    authorizeUrl: 'https://g/authorize',
    clientId: 'https://app.example.com/land',
    redirectUri: 'https://app.example.com/callback',
    state: '', // must NOT be kept
    storage,
    navigate: false,
  });
  assert.ok(req.state.length > 0, 'empty state should have been replaced');
  assert.equal(JSON.parse(storage.getItem('gptbots:wext:login')).state, req.state);
});

test('readAuthorizeCallback rejects a forged empty state against a real stored state', () => {
  const storage = memStorage({
    'gptbots:wext:login': JSON.stringify({ state: 'st-real', codeVerifier: 'v' }),
  });
  try {
    readAuthorizeCallback('?code=c&state=', storage); // attacker sends empty state
    assert.fail('expected StateMismatch');
  } catch (e) {
    assert.ok(e instanceof WorkspaceLoginError);
    assert.equal(e.code, 'StateMismatch');
  }
});

test('readAuthorizeCallback throws MissingRequest with no stored request', () => {
  try {
    readAuthorizeCallback('?code=c&state=s', memStorage());
    assert.fail('expected MissingRequest');
  } catch (e) {
    assert.equal(e.code, 'MissingRequest');
  }
});

test('readAuthorizeCallback throws MissingRequest on corrupt stored JSON', () => {
  const storage = memStorage({ 'gptbots:wext:login': '{not json' });
  try {
    readAuthorizeCallback('?code=c&state=s', storage);
    assert.fail('expected MissingRequest');
  } catch (e) {
    assert.equal(e.code, 'MissingRequest');
  }
});

test('readAuthorizeCallback throws MissingRequest when the stored verifier is absent', () => {
  const storage = memStorage({ 'gptbots:wext:login': JSON.stringify({ state: 's' }) });
  try {
    readAuthorizeCallback('?code=c&state=s', storage);
    assert.fail('expected MissingRequest');
  } catch (e) {
    assert.equal(e.code, 'MissingRequest');
  }
});

test('completeWorkspaceLogin throws NoCallback when there is no code', async () => {
  const storage = memStorage({ 'gptbots:wext:login': JSON.stringify({ state: 's', codeVerifier: 'v' }) });
  await assert.rejects(
    () => completeWorkspaceLogin({ exchangeUrl: '/x', fetch: async () => ({ ok: true }), search: '?foo=1', storage }),
    (e) => e instanceof WorkspaceLoginError && e.code === 'NoCallback',
  );
});

test('completeWorkspaceLogin propagates StateMismatch from a forged callback', async () => {
  const storage = memStorage({ 'gptbots:wext:login': JSON.stringify({ state: 'st-1', codeVerifier: 'v' }) });
  await assert.rejects(
    () =>
      completeWorkspaceLogin({ exchangeUrl: '/x', fetch: async () => ({ ok: true }), search: '?code=c&state=evil', storage }),
    (e) => e instanceof WorkspaceLoginError && e.code === 'StateMismatch',
  );
});

test('completeWorkspaceLogin throws ExchangeFailed on a non-ok backend response', async () => {
  const storage = memStorage({ 'gptbots:wext:login': JSON.stringify({ state: 'st-1', codeVerifier: 'v' }) });
  await assert.rejects(
    () =>
      completeWorkspaceLogin({
        exchangeUrl: '/x',
        fetch: async () => ({ ok: false, status: 401, json: async () => ({}) }),
        search: '?code=c&state=st-1',
        storage,
        strip: false,
      }),
    (e) => e instanceof WorkspaceLoginError && e.code === 'ExchangeFailed',
  );
});

test('completeWorkspaceLogin throws InvalidResponse on invalid JSON', async () => {
  const storage = memStorage({ 'gptbots:wext:login': JSON.stringify({ state: 'st-1', codeVerifier: 'v' }) });
  await assert.rejects(
    () =>
      completeWorkspaceLogin({
        exchangeUrl: '/x',
        fetch: async () => ({ ok: true, status: 200, json: async () => { throw new SyntaxError('bad'); } }),
        search: '?code=c&state=st-1',
        storage,
        strip: false,
      }),
    (e) => e instanceof WorkspaceLoginError && e.code === 'InvalidResponse',
  );
});

// ── FIX #5: consumption deferred to a SUCCESSFUL exchange (transient failure is retryable) ─────────

test('completeWorkspaceLogin keeps the stored request after a transient ExchangeFailed, and a retry succeeds', async () => {
  const storage = memStorage({ 'gptbots:wext:login': JSON.stringify({ state: 'st-1', codeVerifier: 'verifier-abc' }) });
  // First attempt: transient failure (e.g. 502).
  await assert.rejects(
    () =>
      completeWorkspaceLogin({
        exchangeUrl: '/x',
        fetch: async () => ({ ok: false, status: 502, json: async () => ({}) }),
        search: '?code=THE_CODE&state=st-1',
        storage,
        strip: false,
      }),
    (e) => e instanceof WorkspaceLoginError && e.code === 'ExchangeFailed',
  );
  // The verifier must survive so a reload + retry can still exchange the live code.
  assert.equal(storage.getItem('gptbots:wext:login'), JSON.stringify({ state: 'st-1', codeVerifier: 'verifier-abc' }));

  // Second attempt: backend now healthy → succeeds.
  let seen;
  const id = await completeWorkspaceLogin({
    exchangeUrl: '/x',
    fetch: async (url, init) => {
      seen = JSON.parse(init.body);
      return { ok: true, status: 200, json: async () => ({ accountId: 'acc-1', role: 'MEMBER', workspaceId: 'p-1' }) };
    },
    search: '?code=THE_CODE&state=st-1',
    storage,
    strip: false,
  });
  assert.equal(id.accountId, 'acc-1');
  assert.deepEqual(seen, { code: 'THE_CODE', codeVerifier: 'verifier-abc' });
});

test('completeWorkspaceLogin removes the stored request after a successful exchange', async () => {
  const storage = memStorage({ 'gptbots:wext:login': JSON.stringify({ state: 'st-1', codeVerifier: 'verifier-abc' }) });
  await completeWorkspaceLogin({
    exchangeUrl: '/x',
    fetch: async () => ({ ok: true, status: 200, json: async () => ({ accountId: 'acc-1', role: 'MEMBER', workspaceId: 'p-1' }) }),
    search: '?code=THE_CODE&state=st-1',
    storage,
    strip: false,
  });
  assert.equal(storage.getItem('gptbots:wext:login'), null);
});

// ── FIX #7: startWorkspaceLogin must fail loudly when storage is unavailable ───────────────────────

test('startWorkspaceLogin does NOT redirect when the injected storage setItem throws', async () => {
  let redirected = false;
  const throwingStorage = {
    getItem: () => null,
    setItem: () => { throw new Error('sessionStorage disabled'); },
    removeItem: () => {},
  };
  // An injected storage whose setItem throws models a blocked store: the throw must escape and the
  // redirect must never fire (otherwise the callback page cannot find the verifier).
  await assert.rejects(
    () =>
      startWorkspaceLogin({
        authorizeUrl: 'https://g/authorize',
        clientId: 'https://app.example.com/land',
        redirectUri: 'https://app.example.com/callback',
        storage: throwingStorage,
        redirect: () => { redirected = true; },
      }),
    (e) => e instanceof Error && e.message.includes('sessionStorage disabled'),
  );
  assert.equal(redirected, false);
});

test('startWorkspaceLogin throws StorageUnavailable and does NOT redirect when no storage is resolvable (no DOM)', async () => {
  // No storage injected + no sessionStorage in this node runtime → defaultStorage() is undefined.
  let redirected = false;
  await assert.rejects(
    () =>
      startWorkspaceLogin({
        authorizeUrl: 'https://g/authorize',
        clientId: 'https://app.example.com/land',
        redirectUri: 'https://app.example.com/callback',
        redirect: () => { redirected = true; },
      }),
    (e) => e instanceof WorkspaceLoginError && e.code === 'StorageUnavailable',
  );
  assert.equal(redirected, false);
});

// ── FIX (relative authorizeUrl) ────────────────────────────────────────────────────────────────

test('startWorkspaceLogin throws a typed WorkspaceLoginError (not a raw TypeError) for a relative authorizeUrl', async () => {
  const storage = memStorage();
  let redirected = false;
  await assert.rejects(
    () =>
      startWorkspaceLogin({
        authorizeUrl: '/relative',
        clientId: 'https://app.example.com/land',
        redirectUri: 'https://app.example.com/callback',
        storage,
        redirect: () => { redirected = true; },
      }),
    (e) => e instanceof WorkspaceLoginError && e.code === 'InvalidAuthorizeUrl',
  );
  assert.equal(redirected, false);
  // nothing was stashed for a malformed URL
  assert.equal(storage.getItem('gptbots:wext:login'), null);
});

// ── FIX #13: ?error callback handling ────────────────────────────────────────────────────────────

test('readAuthorizeCallback throws AuthorizeError on an OAuth ?error redirect with a matching state', () => {
  const storage = memStorage({
    'gptbots:wext:login': JSON.stringify({ state: 'st-1', codeVerifier: 'v' }),
  });
  try {
    readAuthorizeCallback('?error=access_denied&error_description=user+said+no&state=st-1', storage);
    assert.fail('expected AuthorizeError');
  } catch (e) {
    assert.ok(e instanceof WorkspaceLoginError);
    assert.equal(e.code, 'AuthorizeError');
    assert.ok(e.message.includes('access_denied'), e.message);
  }
  // the stored request is cleared on an authorize error
  assert.equal(storage.getItem('gptbots:wext:login'), null);
});

test('readAuthorizeCallback throws StateMismatch on an ?error redirect with a mismatched state', () => {
  const storage = memStorage({
    'gptbots:wext:login': JSON.stringify({ state: 'st-real', codeVerifier: 'v' }),
  });
  try {
    readAuthorizeCallback('?error=access_denied&state=st-evil', storage);
    assert.fail('expected StateMismatch');
  } catch (e) {
    assert.ok(e instanceof WorkspaceLoginError);
    assert.equal(e.code, 'StateMismatch');
  }
});

test('completeWorkspaceLogin surfaces AuthorizeError from an ?error redirect (not NoCallback)', async () => {
  const storage = memStorage({ 'gptbots:wext:login': JSON.stringify({ state: 'st-1', codeVerifier: 'v' }) });
  await assert.rejects(
    () =>
      completeWorkspaceLogin({
        exchangeUrl: '/x',
        fetch: async () => ({ ok: true }),
        search: '?error=access_denied&state=st-1',
        storage,
      }),
    (e) => e instanceof WorkspaceLoginError && e.code === 'AuthorizeError',
  );
});
