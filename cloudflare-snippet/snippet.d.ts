/**
 * Types for the pasted Cloudflare Snippet (snippet.js). The snippet stays
 * plain JS because customers paste the file itself; this declaration exists
 * so snippet.spec.ts and `tsc --noEmit` can check against it.
 */

export interface SnippetConfig {
  /** Decision endpoint. Empty string disables enforcement: pure passthrough. */
  policyWorkerUrl: string;
  /** The org's adapter key, sent as `Authorization: Bearer`. */
  adapterKey: string;
  /** Hard budget for the decision call, in milliseconds. */
  timeoutMs: number;
  /** 'open' passes traffic when the decision call fails; 'closed' blocks instead. */
  failMode: 'open' | 'closed';
  /** Fraction of requests that get a decision call. Unsampled requests return untouched. */
  sampleRate: number;
  /** Call on every request carrying signature headers, whatever sampleRate says. */
  alwaysSampleSigned: boolean;
}

export function createSnippet(config: SnippetConfig): {
  fetch(request: Request): Promise<Response>;
};

declare const snippet: ReturnType<typeof createSnippet>;
export default snippet;
