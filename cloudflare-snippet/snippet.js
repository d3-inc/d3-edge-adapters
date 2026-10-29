// D3 Edge enforcement as a Cloudflare Snippet — the no-Worker install for
// zones on any paid plan. Paste into Rules → Snippets, fill in CONFIG, and
// scope it with a snippet rule. See README.md in this directory; docs:
// https://ai.d3.com/docs/sdks/cloudflare#paste-a-snippet
// Snippets cannot import packages, so this file is self-contained — it
// mirrors the Worker adapter (@d3-inc/d3-edge-cloudflare-adapter).

const CONFIG = {
  // Your org's API key (dashboard → API keys). The only setting DNA needs.
  apiKey: 'd3_k_REPLACE_ME',
  // false turns DNA off without removing the key: pure passthrough.
  enabled: true,
  // Hard budget for the decision call, in milliseconds.
  timeoutMs: 150,
  // Budget for a request presenting a payment: settlement happens inside the call.
  paymentTimeoutMs: 10000,
  // 'open' passes traffic when the decision call fails; 'closed' blocks instead.
  // A request presenting a payment never falls open, whatever this says.
  failMode: 'open',
  // Fraction of requests that get a decision call. Unsampled requests return
  // untouched — no call, no x-d3-edge header. A payment is never sampled out.
  sampleRate: 1,
  // Call on every request carrying signature headers, whatever sampleRate says.
  alwaysSampleSigned: false,
};

const DEFAULT_ENDPOINT = 'https://edge-api.d3.com/v1/decision';

export default createSnippet(CONFIG);

// Headers forwarded to the policy worker — the same allowlist the Worker
// adapter uses (extractPayload in @d3-inc/d3-edge-core).
const FORWARDED_HEADERS = [
  'signature',
  'signature-input',
  'signature-agent',
  'user-agent',
  'content-digest',
  // These four are how a navigating browser is told from an agent, which picks
  // the 402 or the redirect.
  'accept',
  'sec-fetch-mode',
  'sec-fetch-dest',
  'upgrade-insecure-requests',
  'sec-purpose',
  'x-purpose',
  'purpose',
  // x402 v2 renamed its header and a caller's version is unknowable here, so
  // both names travel and the worker's decoder picks.
  'payment-signature',
  'x-payment',
  'payment-authorization',
];

// Past these a value can never be meaningful, so it must not bloat the decision
// POST — and for a payment header, past its cap is not a payment.
const HEADER_LENGTH_CAPS = new Map([
  ['accept', 256],
  ['sec-fetch-mode', 32],
  ['sec-fetch-dest', 32],
  ['upgrade-insecure-requests', 32],
  ['payment-signature', 4096],
  ['x-payment', 4096],
  ['payment-authorization', 128],
]);

const PAYMENT_HEADERS = ['payment-signature', 'x-payment', 'payment-authorization', 'd3pay-session'];

// `__Host-` pins the cookie to the site's origin: no Domain, Path=/, Secure.
const PAY_SESSION_COOKIE = '__Host-d3pay';

// The cookie's value travels under this name; the raw `Cookie` header never does.
const PAY_SESSION_HEADER = 'd3pay-session';

const PAY_SESSION_MAX_LENGTH = 64;

// Where the credential rides for a caller with no cookie jar.
const PAY_HANDOFF_PARAM = 'd3pay_handoff';

const HANDOFF_ID_LENGTH = 22;

const HANDOFF_SIG_LENGTH = 43;

const BASE64URL = /^[A-Za-z0-9_-]+$/;

// Snippets get 2 MB of memory, so only bodies up to this size are hashed.
const MAX_HASHED_BODY_BYTES = 1_000_000;

// The on switch, as in the npm adapters: an endpoint, or an API key that then
// calls the default one. `policyWorkerUrl` and `adapterKey` are the names a
// CONFIG used before, still read so an old CONFIG pasted into this file works.
export function dnaEndpoint(config) {
  if (String(config.enabled).trim().toLowerCase() === 'false') return undefined;

  const endpoint = config.endpoint ?? config.policyWorkerUrl;
  if (endpoint !== undefined) return endpoint || undefined;
  return config.apiKey ? DEFAULT_ENDPOINT : undefined;
}

export function createSnippet(config) {
  // `||`, not `??`: an empty apiKey must not hide an earlier CONFIG's adapterKey.
  const apiKey = config.apiKey || config.adapterKey;
  const endpoint = dnaEndpoint(config);
  return {
    // Unlike the Worker adapter there is no outcome report: Snippets have no
    // waitUntil, so the request is logged at decision time and nothing more.
    async fetch(request) {
      if (!endpoint) return withEdgeHeader(await fetch(request), 'disabled');

      const paying = requestPresentsPayment(request);
      // No Response clone and no header either: an unsampled request costs
      // what the snippet costs uninstalled. Sampling out a payment would serve
      // a page someone paid for to everyone free, so it is exempt.
      if (!paying && !isSampled(request, config)) return fetch(request);

      let decision;
      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            authorization: `Bearer ${apiKey}`,
          },
          body: JSON.stringify(await extractPayload(request)),
          signal: AbortSignal.timeout(paying ? config.paymentTimeoutMs : config.timeoutMs),
        });
        if (!res.ok) throw new Error(`policy worker HTTP ${res.status}`);
        decision = await res.json();
        if (decision.action !== 'pass' && decision.action !== 'block') {
          throw new Error('policy worker returned an invalid decision');
        }
      } catch (err) {
        console.error('d3-edge policy call failed', err);
        // The page is priced and the charge may already have landed, so
        // falling open here would serve a paid page free.
        if (paying) return paymentUnavailableResponse();
        // Enforcement failure must never take the site down, unless opted in.
        if (config.failMode === 'closed') return blockResponse({}, 'fail-closed');
        return withEdgeHeader(await fetch(request), 'fail-open');
      }

      if (decision.action === 'block') return blockResponse(decision, 'block');

      if (decision.payment?.status !== undefined) {
        return buildPaymentResponse(decision.payment);
      }

      const response = await fetch(stripPaymentCredential(request));
      return withPaymentHeaders(withEdgeHeader(response, 'pass'), decision.payment);
    },
  };
}

function isSampled(request, config) {
  if (Math.random() < config.sampleRate) return true;
  return (
    config.alwaysSampleSigned &&
    (request.headers.has('signature') || request.headers.has('signature-input'))
  );
}

// ── D3 Pay credentials ───────────────────────────────────────────────────────
// Presence, never a decode: this runs on the customer's own zone, which must
// not parse a payment.

// All three places a credential rides. Miss one and a redemption gets the
// hot-path budget, overruns it, and comes back a block.
function requestPresentsPayment(request) {
  for (const name of PAYMENT_HEADERS) {
    const value = request.headers.get(name);
    const cap = HEADER_LENGTH_CAPS.get(name) ?? PAY_SESSION_MAX_LENGTH;
    if (value !== null && value.length > 0 && value.length <= cap) return true;
  }

  const cookie = readSessionCookie(request.headers.get('cookie'));
  if (cookie !== null && cookie.length > 0 && cookie.length <= PAY_SESSION_MAX_LENGTH) return true;

  return handoffFromUrl(request.url) !== null;
}

function isWellFormedHandoff(token) {
  const dot = token.indexOf('.');
  if (dot !== HANDOFF_ID_LENGTH) return false;

  const signature = token.slice(dot + 1);
  return (
    signature.length === HANDOFF_SIG_LENGTH &&
    BASE64URL.test(token.slice(0, dot)) &&
    BASE64URL.test(signature)
  );
}

function handoffFromUrl(url) {
  const query = url.indexOf('?');
  if (query === -1) return null;

  const value = new URLSearchParams(url.slice(query + 1)).get(PAY_HANDOFF_PARAM);
  return value !== null && isWellFormedHandoff(value) ? value : null;
}

function stripHandoffParam(url) {
  const query = url.indexOf('?');
  if (query === -1) return url;

  const params = new URLSearchParams(url.slice(query + 1));
  params.delete(PAY_HANDOFF_PARAM);
  const rest = params.toString();
  return rest ? `${url.slice(0, query)}?${rest}` : url.slice(0, query);
}

function readSessionCookie(cookieHeader) {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;

    if (part.slice(0, eq).trim() === PAY_SESSION_COOKIE) return part.slice(eq + 1).trim();
  }

  return null;
}

// The Cookie header with our cookie removed, or null when nothing is left.
function stripSessionCookie(cookieHeader) {
  const kept = cookieHeader
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part.length > 0 && !part.startsWith(`${PAY_SESSION_COOKIE}=`));
  return kept.length > 0 ? kept.join('; ') : null;
}

// Runs whatever requestPresentsPayment said: an oversized value is not a
// payment, and it still must not reach the origin.
function stripPaymentCredential(request) {
  const cookie = request.headers.get('cookie');
  const hasCookie = cookie !== null && readSessionCookie(cookie) !== null;
  const url = stripHandoffParam(request.url);
  const hasHeader = PAYMENT_HEADERS.some((name) => request.headers.has(name));
  if (!hasCookie && !hasHeader && url === request.url) return request;

  const headers = new Headers(request.headers);
  for (const name of PAYMENT_HEADERS) headers.delete(name);

  if (hasCookie) {
    const kept = stripSessionCookie(cookie);
    if (kept === null) headers.delete('cookie');
    else headers.set('cookie', kept);
  }

  if (url === request.url) return new Request(request, { headers });

  const body = request.method === 'GET' || request.method === 'HEAD' ? undefined : request.body;
  return new Request(url, {
    method: request.method,
    headers,
    body,
    redirect: request.redirect,
    signal: request.signal,
    // A streamed body needs it on undici, and workerd ignores it.
    ...(body ? { duplex: 'half' } : {}),
  });
}

// ── The payment answer ───────────────────────────────────────────────────────
// A status, some headers and a string, copied: the snippet never learns what a
// facilitator is, nor the payment protocol's own header names.

// These values are provider and tenant authored, and this is the last place
// before a Headers object. Dropped rather than escaped: none of it is worth a 500.
const HEADER_SAFE_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/;

const HEADER_SAFE_VALUE = /^[\x20-\x7e]{1,8192}$/;

function headerSafePaymentHeaders(headers) {
  const safe = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    if (HEADER_SAFE_NAME.test(name) && HEADER_SAFE_VALUE.test(value)) safe[name] = value;
  }

  return safe;
}

function isRedirect(status) {
  return status >= 300 && status <= 399;
}

function paymentEdgeMode(status) {
  if (status === 402) return 'payment-required';

  return isRedirect(status) ? 'payment-redirect' : 'fail-closed';
}

function buildPaymentResponse(payment) {
  const status = payment.status ?? 502;
  return new Response(payment.body ?? null, {
    status,
    headers: {
      // A JSON type on a redirect misleads the client that follows it.
      ...(isRedirect(status) ? {} : { 'content-type': 'application/json; charset=utf-8' }),
      'cache-control': 'no-store',
      ...headerSafePaymentHeaders(payment.headers),
      'x-d3-edge': paymentEdgeMode(status),
    },
  });
}

// Overwriting the origin's Set-Cookie would log the visitor out of the site to
// hand them ours; overwriting its CORS list would revoke a browser's access to
// headers it deliberately exposed.
const MERGED_HEADERS = new Set(['access-control-expose-headers', 'set-cookie']);

function withPaymentHeaders(response, payment) {
  const safe = headerSafePaymentHeaders(payment?.headers);
  if (Object.keys(safe).length === 0) return response;

  // The origin's headers are immutable until the response is re-wrapped.
  const copy = new Response(response.body, response);
  for (const [name, value] of Object.entries(safe)) {
    if (MERGED_HEADERS.has(name.toLowerCase()) && copy.headers.has(name)) copy.headers.append(name, value);
    else copy.headers.set(name, value);
  }

  return copy;
}

function paymentUnavailableResponse() {
  return new Response(JSON.stringify({ error: 'payment_unavailable' }), {
    status: 502,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-d3-edge': 'fail-closed',
    },
  });
}

async function extractPayload(request) {
  const url = new URL(request.url);

  const headers = {};
  for (const name of FORWARDED_HEADERS) {
    const value = request.headers.get(name);
    if (value === null) continue;

    const cap = HEADER_LENGTH_CAPS.get(name);
    if (cap !== undefined && value.length > cap) continue;

    headers[name] = value;
  }

  // One cookie by name: the `Cookie` header itself is the site's and stays there.
  const session = readSessionCookie(request.headers.get('cookie'));
  if (session !== null && session.length > 0 && session.length <= PAY_SESSION_MAX_LENGTH) {
    headers[PAY_SESSION_HEADER] = session;
  }

  // Overwrite content-digest with the real body's digest so a tampered body
  // fails verification downstream — never forward the client's claim. A body
  // too large to hash strips the claim instead: the request then classifies
  // as unverified rather than carrying a digest nothing checked.
  const canHaveBody = request.method !== 'GET' && request.method !== 'HEAD';
  if (canHaveBody && request.body !== null) {
    const body = await readBodyUpTo(request, MAX_HASHED_BODY_BYTES);
    if (body === null) {
      delete headers['content-digest'];
    } else if (body.byteLength > 0 || 'content-digest' in headers) {
      headers['content-digest'] = await sha256ContentDigest(body);
    }
  } else if ('content-digest' in headers) {
    // An empty body must not smuggle a forged digest past this.
    headers['content-digest'] = await sha256ContentDigest(new Uint8Array(0));
  }

  return {
    requestId: crypto.randomUUID(),
    ip: request.headers.get('cf-connecting-ip') ?? undefined,
    method: request.method,
    url: url.pathname + url.search,
    host: url.host,
    timestamp: new Date().toISOString(),
    headers,
  };
}

// Reads a clone of the body, giving up (null) past maxBytes — Content-Length
// can lie, so the cap is enforced on actual bytes, not the header.
async function readBodyUpTo(request, maxBytes) {
  const reader = request.clone().body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      // Best-effort, not awaited: cancelling a cloned body's reader only
      // settles once the clone's other branch is consumed on some runtimes.
      reader.cancel().catch(() => {});
      return null;
    }

    chunks.push(value);
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return body;
}

// RFC 9530 Content-Digest field value, sha-256 only.
async function sha256ContentDigest(body) {
  const digest = await crypto.subtle.digest('SHA-256', body);
  let binary = '';
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return `sha-256=:${btoa(binary)}:`;
}

function blockResponse(decision, mode) {
  return new Response(
    JSON.stringify({
      blocked: true,
      ruleId: decision.ruleId,
      tier: decision.verdict?.tier,
      identity: decision.verdict?.identity,
    }),
    {
      status: 403,
      headers: { 'content-type': 'application/json; charset=utf-8', 'x-d3-edge': mode },
    }
  );
}

function withEdgeHeader(response, mode) {
  const out = new Response(response.body, response);
  out.headers.set('x-d3-edge', mode);
  return out;
}
