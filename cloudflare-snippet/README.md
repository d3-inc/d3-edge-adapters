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

`CONFIG` at the top of the file, mapping onto the worker adapters'
variables where they exist:

| Constant             | Worker equivalent            | Default | What it does                                                                              |
| -------------------- | ---------------------------- | ------- | ----------------------------------------------------------------------------------------- |
| `policyWorkerUrl`    | `POLICY_WORKER_URL`          | set     | Decision endpoint. **Empty string means pure passthrough.**                               |
| `adapterKey`         | `POLICY_ADAPTER_KEY`         | —       | Your org's key, bearer for the decision call.                                             |
| `timeoutMs`          | `POLICY_TIMEOUT_MS`          | `150`   | Hard budget for the decision call.                                                        |
| `paymentTimeoutMs`   | `POLICY_PAYMENT_TIMEOUT_MS`  | `10000` | Budget for a request presenting a payment — settlement happens inside it.                 |
| `failMode`           | `FAIL_MODE`                  | `open`  | `open`: pass traffic when the call fails. `closed`: block instead.                        |
| `sampleRate`         | —                            | `1`     | Fraction of requests that get a decision call. Unsampled requests return untouched.       |
| `alwaysSampleSigned` | —                            | `false` | Call on every request carrying signature headers, whatever `sampleRate` says.             |

`ORIGIN` and `ORIGIN_URL` don't exist here: pass-traffic continues to
whatever your zone already routes to.

## Response shape

Every sampled response carries an `x-d3-edge` header: `disabled`,
`pass`, `block`, `fail-open`, `fail-closed`, `payment-required`, or
`payment-redirect`. An unsampled request (`sampleRate` below `1`)
returns untouched, with no header at all. A blocked request gets a `403`
with a JSON body:

```json
{ "blocked": true, "ruleId": "…", "tier": "…", "identity": "…" }
```

## Paid routes (D3 Pay)

The snippet carries [D3 Pay](../PROTOCOL.md#paid-routes). If you price a
route in the dashboard, an unpaid request gets the `402` the decision
endpoint hands back — or a `302` to the pay app when a browser is
navigating — and the page is served once the visitor's agent presents a
credential:

- **The credential is forwarded, never parsed.** A `__Host-d3pay`
  cookie travels to the decision endpoint as a `d3pay-session` header,
  on its own; the rest of the visitor's `Cookie` header never leaves
  your zone. A `Payment-Authorization` header or a `?d3pay_handoff=` on
  the URL works the same way for an agent with no cookie jar.
- **A paying request gets its own budget** (`paymentTimeoutMs`, 10 s),
  because settlement happens inside that call.
- **A paying request never falls open.** Whatever `failMode` says, a
  failed decision call on a request carrying a credential answers `502
  {"error":"payment_unavailable"}`. The page is priced and the charge
  may already have landed; serving it free is the one wrong answer.
- **A paying request is never left to the sample draw.** `sampleRate`
  does not apply to it — unsampled, someone would have paid for a page
  that was then served to everyone free.
- **Your origin never sees a credential.** The payment headers are
  dropped, our cookie is taken out of `Cookie` (yours are left alone),
  and `d3pay_handoff` is removed from the URL before the origin fetch.
  The receipt and the session cookie are added to your origin's own
  response, `Set-Cookie` appended rather than replaced.

This costs no extra subrequest: it is the same decision call, reading a
field it already returns. Nothing changes for a site with no priced
routes.

## Notes

- There is no observe-only switch in the snippet. Observe-only is a
  policy posture: with a `log-only` policy in the dashboard (the
  default), every decision comes back `pass` — traffic is recorded,
  nothing blocks. The snippet just acts on the verdict it's given.
- With `sampleRate` below `1`, most responses carry no `x-d3-edge`
  header, so a plain `curl` is an unreliable install check. Set
  `alwaysSampleSigned: true` and send
  `curl -sI -H 'signature-input: x' https://www.example.com/` — that
  request is guaranteed a decision call and comes back tagged.
- The snippet makes one call per sampled request — the decision call. There is
  no after-response outcome report (Snippets have no `waitUntil`);
  requests are classified and logged at decision time.
- Signed request bodies over 1 MB — an agent uploading a large file,
  which is rare — classify as unverified rather than proven (Snippets
  get 2 MB of memory). If large signed uploads matter to your site, use
  a [worker install](https://ai.d3.com/docs/sdks/cloudflare).
- Tested by [`snippet.spec.ts`](./snippet.spec.ts): `npm test` at the
  repo root.
