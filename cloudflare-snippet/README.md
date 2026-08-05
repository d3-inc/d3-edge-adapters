# D3 Edge Cloudflare Snippet

[D3 Edge](https://ai.d3.com) enforcement as a [Cloudflare
Snippet](https://developers.cloudflare.com/rules/snippets/) — a single
file pasted into your zone, no Worker deploy. Snippets are included at
no extra cost on every paid Cloudflare plan (the free tier doesn't have
them). Same decision, same `403`, same fail-open as the worker installs.

## Install

1. In the Cloudflare dashboard: your zone → **Rules → Snippets →
   Create a Snippet**.
2. Paste [`snippet.js`](./snippet.js) and fill in `adapterKey` — create
   the key at
   [dashboard.d3.com/keys](https://dashboard.d3.com/keys) — plus
   anything else in `CONFIG` you want to change.
3. Scope it with a snippet rule like `http.host eq "www.example.com"`
   and deploy.

Check it's live with `curl -sI https://www.example.com/` — every
response carries an `x-d3-edge` header once it is.

## Configuration

`CONFIG` at the top of the file, mapping one-to-one onto the worker
adapters' variables:

| Constant          | Worker equivalent    | Default | What it does                                                        |
| ----------------- | -------------------- | ------- | -------------------------------------------------------------------- |
| `policyWorkerUrl` | `POLICY_WORKER_URL`  | set     | Decision endpoint. **Empty string means pure passthrough.**          |
| `adapterKey`      | `POLICY_ADAPTER_KEY` | —       | Your org's key, bearer for the decision call.                        |
| `timeoutMs`       | `POLICY_TIMEOUT_MS`  | `150`   | Hard budget for the decision call.                                   |
| `failMode`        | `FAIL_MODE`          | `open`  | `open`: pass traffic when the call fails. `closed`: block instead.   |

`ORIGIN` and `ORIGIN_URL` don't exist here: pass-traffic continues to
whatever your zone already routes to.

## Response shape

Every response carries an `x-d3-edge` header: `disabled`, `pass`,
`block`, `fail-open`, or `fail-closed`. A blocked request gets a `403`
with a JSON body:

```json
{ "blocked": true, "ruleId": "…", "tier": "…", "identity": "…" }
```

## Notes

- The snippet makes one call per request — the decision call. There is
  no after-response outcome report (Snippets have no `waitUntil`);
  requests are classified and logged at decision time.
- Signed request bodies over 1 MB — an agent uploading a large file,
  which is rare — classify as unverified rather than proven (Snippets
  get 2 MB of memory). If large signed uploads matter to your site, use
  a [worker install](https://ai.d3.com/docs/sdks/cloudflare).
- Tested by [`snippet.spec.ts`](./snippet.spec.ts): `npm test` at the
  repo root.
