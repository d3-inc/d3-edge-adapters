import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import snippetDefault, { createSnippet, type SnippetConfig } from './snippet.js';

// Mirrors ClientDecision / RequestPayload from @d3-inc/d3-edge-core — inlined
// so this repo has no dependency beyond vitest.
interface Verdict {
  verified: boolean;
  tier: string;
  reason?: string;
  identity?: string;
}

interface ClientDecision {
  action: string;
  policyAction?: string;
  ruleId?: string;
  verdict?: Verdict;
}

interface RequestPayload {
  requestId?: string;
  ip?: string;
  method: string;
  url: string;
  host: string;
  timestamp?: string | number;
  headers: Record<string, string>;
}

const POLICY_URL = 'https://edge-api.d3.com/v1/decision';
const KEY = 'd3_k_' + 'a'.repeat(43) + 'AAAAAA';

const BASE_CONFIG: SnippetConfig = {
  policyWorkerUrl: POLICY_URL,
  adapterKey: KEY,
  timeoutMs: 1000,
  failMode: 'open',
  sampleRate: 1,
  alwaysSampleSigned: false,
};

afterEach(() => {
  vi.unstubAllGlobals();
});

interface FetchLog {
  policyCalls: { headers: Headers; payload: RequestPayload }[];
  originCalls: Request[];
  otherCalls: string[];
}

function stubOutbound(decision: ClientDecision | { status: number } | 'hang'): FetchLog {
  const log: FetchLog = { policyCalls: [], originCalls: [], otherCalls: [] };
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    if (request.url === POLICY_URL) {
      if (decision === 'hang') {
        return new Promise<Response>((_, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
        });
      }

      if ('status' in decision && !('action' in decision)) {
        return new Response('boom', { status: decision.status });
      }

      log.policyCalls.push({
        headers: request.headers,
        payload: (await request.json()) as RequestPayload,
      });
      return Response.json(decision);
    }

    // The snippet passes through via fetch(request): a Request input is the origin.
    if (input instanceof Request) {
      log.originCalls.push(request);
      return new Response('origin says hi', { status: 200 });
    }

    log.otherCalls.push(request.url);
    return new Response(null, { status: 500 });
  });
  return log;
}

function siteRequest(init?: RequestInit & { url?: string }): Request {
  return new Request(init?.url ?? 'https://ai.d3.com/page?x=1', {
    headers: { 'user-agent': 'GPTBot/1.0', 'cf-connecting-ip': '203.0.113.7' },
    ...init,
    // Node's fetch (undici) requires duplex when a request carries a body;
    // the Workers runtime does not — harmless there.
    ...(init?.body ? { duplex: 'half' } : {}),
  } as RequestInit);
}

function run(request: Request, overrides?: Partial<SnippetConfig>): Promise<Response> {
  return createSnippet({ ...BASE_CONFIG, ...overrides }).fetch(request);
}

describe('enforcement', () => {
  it('should proxy to origin on pass and tag the response', async () => {
    const log = stubOutbound({ action: 'pass', policyAction: 'log-only' });
    const res = await run(siteRequest());

    expect(res.status).toBe(200);
    expect(await res.text()).toBe('origin says hi');
    expect(res.headers.get('x-d3-edge')).toBe('pass');
    expect(log.originCalls).toHaveLength(1);

    const call = log.policyCalls[0];
    expect(call.headers.get('authorization')).toBe(`Bearer ${KEY}`);
    expect(call.payload).toMatchObject({
      method: 'GET',
      url: '/page?x=1',
      host: 'ai.d3.com',
      ip: '203.0.113.7',
    });
    expect(call.payload.headers['user-agent']).toBe('GPTBot/1.0');
    expect(call.payload.requestId).toBeTruthy();
  });

  it('should return a machine-readable 403 on block without touching the origin', async () => {
    const log = stubOutbound({
      action: 'block',
      policyAction: 'block',
      ruleId: 'block:gptbot',
      verdict: { verified: false, tier: 'derived', reason: 'no-signature', identity: 'gptbot' },
    });
    const res = await run(siteRequest());

    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({
      blocked: true,
      ruleId: 'block:gptbot',
      tier: 'derived',
      identity: 'gptbot',
    });
    expect(res.headers.get('x-d3-edge')).toBe('block');
    expect(log.originCalls).toHaveLength(0);
  });
});

describe('content-digest attestation', () => {
  // sha-256("hello"), the fixed vector the recompute must produce.
  const HELLO_DIGEST = 'sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:';
  const EMPTY_DIGEST = 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:';

  it("should overwrite the client's claimed digest with the real body's", async () => {
    const log = stubOutbound({ action: 'pass' });
    await run(
      siteRequest({ method: 'POST', body: 'hello', headers: { 'content-digest': 'sha-256=:forged=:' } })
    );
    expect(log.policyCalls[0].payload.headers['content-digest']).toBe(HELLO_DIGEST);
  });

  it('should not let an empty body smuggle a forged digest through', async () => {
    const log = stubOutbound({ action: 'pass' });
    await run(siteRequest({ method: 'POST', headers: { 'content-digest': 'sha-256=:forged=:' } }));
    expect(log.policyCalls[0].payload.headers['content-digest']).toBe(EMPTY_DIGEST);
  });

  it('should strip the claim instead of hashing a body past the memory cap', async () => {
    const log = stubOutbound({ action: 'pass' });
    await run(
      siteRequest({
        method: 'POST',
        body: 'x'.repeat(1_000_001),
        headers: { 'content-digest': 'sha-256=:forged=:' },
      })
    );
    expect(log.policyCalls[0].payload.headers['content-digest']).toBeUndefined();
  });

  it('should add no digest to a body-less request without a claim', async () => {
    const log = stubOutbound({ action: 'pass' });
    await run(siteRequest());
    expect(log.policyCalls[0].payload.headers['content-digest']).toBeUndefined();
  });
});

describe('fail-open (enforcement failure must never take the site down)', () => {
  afterEach(() => vi.restoreAllMocks());

  it('should pass traffic when the policy worker errors', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const log = stubOutbound({ status: 500 });
    const res = await run(siteRequest());
    expect(res.status).toBe(200);
    expect(res.headers.get('x-d3-edge')).toBe('fail-open');
    expect(log.originCalls).toHaveLength(1);
  });

  it('should pass traffic when the policy call exceeds its timeout budget', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const log = stubOutbound('hang');
    const res = await run(siteRequest(), { timeoutMs: 20 });
    expect(res.status).toBe(200);
    expect(res.headers.get('x-d3-edge')).toBe('fail-open');
    expect(log.originCalls).toHaveLength(1);
  });

  it('should pass traffic on an invalid decision body', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    stubOutbound({ action: 'self-destruct' } as unknown as ClientDecision);
    const res = await run(siteRequest());
    expect(res.headers.get('x-d3-edge')).toBe('fail-open');
  });

  it('should block instead when the site opted into fail-closed', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const log = stubOutbound({ status: 500 });
    const res = await run(siteRequest(), { failMode: 'closed' });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-d3-edge')).toBe('fail-closed');
    expect(log.originCalls).toHaveLength(0);
  });
});

describe('traffic sampling', () => {
  afterEach(() => vi.restoreAllMocks());

  it('should return an unsampled request untouched: no call, no header', async () => {
    vi.spyOn(Math, 'random').mockReturnValue(0.99);
    const log = stubOutbound({ action: 'pass' });
    const res = await run(siteRequest(), { sampleRate: 0.05 });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('origin says hi');
    expect(res.headers.get('x-d3-edge')).toBeNull();
    expect(log.policyCalls).toHaveLength(0);
    expect(log.originCalls).toHaveLength(1);
  });

  it('should call and tag a request that wins the sample draw', async () => {
    vi.spyOn(Math, 'random').mockReturnValue(0.01);
    const log = stubOutbound({ action: 'pass' });
    const res = await run(siteRequest(), { sampleRate: 0.05 });
    expect(res.headers.get('x-d3-edge')).toBe('pass');
    expect(log.policyCalls).toHaveLength(1);
  });

  it('should always sample signed requests when alwaysSampleSigned is set', async () => {
    const log = stubOutbound({ action: 'pass' });
    const res = await run(siteRequest({ headers: { 'signature-input': 'sig1=("@authority")' } }), {
      sampleRate: 0,
      alwaysSampleSigned: true,
    });
    expect(res.headers.get('x-d3-edge')).toBe('pass');
    expect(log.policyCalls).toHaveLength(1);
  });

  it('should not exempt signed requests from sampling by default', async () => {
    const log = stubOutbound({ action: 'pass' });
    const res = await run(siteRequest({ headers: { 'signature-input': 'sig1=("@authority")' } }), {
      sampleRate: 0,
    });
    expect(res.headers.get('x-d3-edge')).toBeNull();
    expect(log.policyCalls).toHaveLength(0);
    expect(log.originCalls).toHaveLength(1);
  });
});

describe('snippet-specific behavior', () => {
  it('should pass straight through when no policy worker is configured', async () => {
    const log = stubOutbound({ action: 'pass' });
    const res = await run(siteRequest(), { policyWorkerUrl: '' });
    expect(res.status).toBe(200);
    expect(res.headers.get('x-d3-edge')).toBe('disabled');
    expect(log.policyCalls).toHaveLength(0);
    expect(log.originCalls).toHaveLength(1);
  });

  it('should make no subrequests beyond the decision call and the origin', async () => {
    // No outcome report exists in the snippet: Snippets have no waitUntil, and
    // Pro's 2-subrequest budget could not afford one anyway.
    const log = stubOutbound({ action: 'pass' });
    await run(siteRequest());
    expect(log.otherCalls).toHaveLength(0);
    expect(log.policyCalls).toHaveLength(1);
    expect(log.originCalls).toHaveLength(1);
  });

  it('should export a default handler wired to the pasteable CONFIG', () => {
    expect(snippetDefault.fetch).toBeTypeOf('function');
  });

  it('should stay a single dependency-free file under the 32 KB Snippets limit', () => {
    const source = readFileSync(new URL('./snippet.js', import.meta.url), 'utf8');
    expect(/^import\s/m.test(source)).toBe(false);
    expect(new TextEncoder().encode(source).length).toBeLessThan(32 * 1024);
  });
});
