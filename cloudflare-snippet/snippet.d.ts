/**
 * Types for the pasted Cloudflare Snippet (snippet.js). The snippet stays
 * plain JS because customers paste the file itself; this declaration exists
 * so snippet.spec.ts and `tsc --noEmit` can check against it.
 */

export interface SnippetConfig {
  /** The org's API key, sent as `Authorization: Bearer`. Set ⇒ DNA is on, calling the default endpoint. */
  apiKey?: string;
  /** Decision endpoint override. Empty string disables enforcement: pure passthrough. */
  endpoint?: string;
  /** `false` disables enforcement without removing the key. */
  enabled?: boolean;
  /** @deprecated `endpoint`. Unlike `apiKey`, `adapterKey` needs this set to switch DNA on. */
  policyWorkerUrl?: string;
  /** @deprecated `apiKey` */
  adapterKey?: string;
  /** Hard budget for the decision call, in milliseconds. */
  timeoutMs: number;
  /** Budget for a request presenting a payment, in milliseconds — settlement happens inside it. */
  paymentTimeoutMs: number;
  /** 'open' passes traffic when the decision call fails; 'closed' blocks instead.
   *  A request presenting a payment never falls open, whatever this says. */
  failMode: 'open' | 'closed';
  /** Fraction of requests that get a decision call. Unsampled requests return
   *  untouched; a request presenting a payment is always sampled. */
  sampleRate: number;
  /** Call on every request carrying signature headers, whatever sampleRate says. */
  alwaysSampleSigned: boolean;
}

export function dnaEndpoint(config: SnippetConfig): string | undefined;

export function createSnippet(config: SnippetConfig): {
  fetch(request: Request): Promise<Response>;
};

declare const snippet: ReturnType<typeof createSnippet>;
export default snippet;
