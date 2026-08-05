// D3 Edge enforcement as a Cloudflare Snippet — the no-Worker install for
// zones on any paid plan. Paste into Rules → Snippets, fill in CONFIG, and
// scope it with a snippet rule. See README.md in this directory; docs:
// https://ai.d3.com/docs/sdks/cloudflare#paste-a-snippet
// Snippets cannot import packages, so this file is self-contained — it
// mirrors the Worker adapter (@d3-inc/d3-edge-cloudflare-adapter).

const CONFIG = {
  // Decision endpoint. An empty string is the kill switch: pure passthrough.
  policyWorkerUrl: 'https://edge-api.d3.com/v1/decision',
  // Your org's adapter key (dashboard → Keys).
  adapterKey: 'd3_k_REPLACE_ME',
  // Hard budget for the decision call, in milliseconds.
  timeoutMs: 150,
  // 'open' passes traffic when the decision call fails; 'closed' blocks instead.
  failMode: 'open',
  // Fraction of requests that get a decision call. Unsampled requests return
  // untouched — no call, no x-d3-edge header.
  sampleRate: 1,
  // Call on every request carrying signature headers, whatever sampleRate says.
  alwaysSampleSigned: false,
};

export default createSnippet(CONFIG);

// Headers forwarded to the policy worker — the same allowlist the Worker
// adapter uses (extractPayload in @d3-inc/d3-edge-core).
const FORWARDED_HEADERS = [
  'signature',
  'signature-input',
  'signature-agent',
  'user-agent',
  'content-digest',
  'sec-purpose',
  'x-purpose',
  'purpose',
];

// Snippets get 2 MB of memory, so only bodies up to this size are hashed.
const MAX_HASHED_BODY_BYTES = 1_000_000;

export function createSnippet(config) {
  return {
    // Unlike the Worker adapter there is no outcome report: Snippets have no
    // waitUntil, so the request is logged at decision time and nothing more.
    async fetch(request) {
      if (!config.policyWorkerUrl) return withEdgeHeader(await fetch(request), 'disabled');
      // No Response clone and no header either: an unsampled request costs
      // what the snippet costs uninstalled.
      if (!isSampled(request, config)) return fetch(request);

      let decision;
      try {
        const res = await fetch(config.policyWorkerUrl, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            authorization: `Bearer ${config.adapterKey}`,
          },
          body: JSON.stringify(await extractPayload(request)),
          signal: AbortSignal.timeout(config.timeoutMs),
        });
        if (!res.ok) throw new Error(`policy worker HTTP ${res.status}`);
        decision = await res.json();
        if (decision.action !== 'pass' && decision.action !== 'block') {
          throw new Error('policy worker returned an invalid decision');
        }
      } catch (err) {
        // Enforcement failure must never take the site down, unless opted in.
        console.error('d3-edge policy call failed', err);
        if (config.failMode === 'closed') return blockResponse({}, 'fail-closed');
        return withEdgeHeader(await fetch(request), 'fail-open');
      }

      if (decision.action === 'block') return blockResponse(decision, 'block');
      return withEdgeHeader(await fetch(request), 'pass');
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

async function extractPayload(request) {
  const url = new URL(request.url);

  const headers = {};
  for (const name of FORWARDED_HEADERS) {
    const value = request.headers.get(name);
    if (value !== null) headers[name] = value;
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
