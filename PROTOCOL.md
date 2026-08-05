# The decision protocol

Every adapter in this repo — and every one you write yourself — speaks the
same contract to the D3 Edge decision endpoint: one JSON `POST` per
request, in, a `pass` or `block` out. This page is that contract. If you
are installing an existing adapter you don't need it; read it to write a
new one, or to understand exactly what leaves your infrastructure.

Nothing here is negotiated or versioned per adapter. The endpoint accepts
unknown payload fields and adapters must ignore unknown response fields,
so the contract grows additively — but a field that exists means what it
says here.

## The call

```
POST https://edge-api.d3.com/v1/decision
Authorization: Bearer <your adapter key>
Content-Type: application/json
```

The key is per-org, created in the dashboard, and carries the org that
scopes every policy lookup. It is not host-scoped: one key may report any
host you own.

One call per request, on the request path, with a hard timeout you
choose (150 ms is the default across this repo). It is the only blocking
call an adapter makes.

## Request

| Field       | Type                  | Required | Meaning                                                                       |
| ----------- | --------------------- | -------- | ----------------------------------------------------------------------------- |
| `method`    | string                | yes      | The agent's HTTP method.                                                      |
| `url`       | string                | yes      | Request target: path plus query, e.g. `/search?q=1`. Not an absolute URL.     |
| `host`      | string                | yes      | The `Host` / authority the agent addressed.                                   |
| `headers`   | object                | yes      | Lowercase-keyed subset of the agent's headers — see below.                     |
| `requestId` | string (≤64)          | no       | Your correlation id. Links this decision to an outcome report and to logs.     |
| `ip`        | string                | no       | The agent's IP. Used for fingerprint matching, then hashed or dropped.        |
| `timestamp` | ISO-8601 or epoch sec | no       | When you observed the request. Informational.                                 |

`url` carries the query because signatures may cover `@query`; strip
nothing. `host` must be the authority the agent used, not your origin's
internal hostname — policy is per `(org, host)`.

### Which headers to forward

Exactly these, when present. A signature covering a header outside this
list comes back `missing-headers`:

```
signature  signature-input  signature-agent  user-agent
content-digest  sec-purpose  x-purpose  purpose
```

Forwarding more is harmless but pointless; forwarding fewer breaks
verification. Do not forward cookies, `authorization`, or anything else
the agent sent — the endpoint has no use for them.

### `content-digest` is yours to compute, never to relay

RFC 9421 signatures cover headers, never body bytes. A signed request
binds its body only indirectly, through an RFC 9530 `Content-Digest`
header that the signature covers. So the digest the client sends is a
*claim*: relaying it verbatim would let a tampered body verify.

An adapter computes the digest itself over the bytes it actually
received, and overwrites whatever the client claimed:

- Body present → `content-digest: sha-256=:<base64 of SHA-256>:`
- No body, but a claimed digest → overwrite with the digest of the empty
  body. An empty body must not smuggle a forged claim through.
- No body and no claim → send no `content-digest` at all. Adding one
  fails body-less signed requests as `insufficient-coverage`.
- Body too large to hash within your limits → **strip** the header. The
  request then classifies as unverified, which is honest; forwarding an
  unchecked claim is not.

`GET` and `HEAD` never have a body worth hashing, which is nearly all
agent traffic.

## Response

`200` with a JSON decision:

| Field          | Type                          | Meaning                                                       |
| -------------- | ----------------------------- | ------------------------------------------------------------- |
| `action`       | `"pass"` \| `"block"`         | What to do. The only field an adapter must handle.             |
| `policyAction` | `"allow"`/`"block"`/`"log-only"` | What the matched rule asked for. `log-only` yields `pass`. |
| `ruleId`       | string                        | The rule that decided. Absent when the org default decided.   |
| `verdict`      | object                        | How the agent was classified — see below.                     |
| `failOpen`     | boolean                       | Set when the endpoint itself fell back rather than evaluating. |

Treat any `action` that is neither `pass` nor `block` as a failure and
apply your fail mode. Do not invent a default.

### The verdict

Rich, and mostly for logging and response headers rather than
enforcement. The fields adapters generally surface:

| Field      | Meaning                                                                            |
| ---------- | ---------------------------------------------------------------------------------- |
| `tier`     | `proven` \| `claimed` \| `derived` \| `spoofed` \| `unverified`, strongest first.  |
| `identity` | Canonical agent name when known, else the claimed `Signature-Agent` hostname.      |
| `reason`   | `ok`, or why verification did not reach `proven` (`expired`, `unknown-key`, …).    |
| `purpose`  | The purposes we assert this agent serves.                                          |

Unsigned traffic is classified, not rejected: no signature means a
`derived`, `spoofed`, or `unverified` verdict, and policy decides from
there.

### Errors

`401` or `503` with `{ "error": "<reason>" }` — `unknown-key`, `expired`,
`revoked`, or `not-configured`. There is no `403`; a valid key may report
any host.

**Log the reason.** A dead or revoked key looks exactly like a working
site once you fail open, and that log line in your own platform logs is
how it gets diagnosed.

## What an adapter must do

The protocol is half the contract; the rest is behavior every adapter in
this repo implements identically.

1. **Fail open.** A timeout, transport error, non-`200`, or unparseable
   response passes the request through. Enforcement breaking must never
   take the site down. A `closed` fail mode is worth offering as an
   opt-in, never as the default.
2. **Bound the call.** A hard timeout, not a socket default. If the
   platform cannot enforce one, it cannot host a correct adapter.
3. **Ship a kill switch.** An unset decision endpoint means pure
   passthrough, with no call and no dependency on us.
4. **Block with `403`** and a JSON body:
   ```json
   { "blocked": true, "ruleId": "…", "tier": "…", "identity": "…" }
   ```
5. **Tag every response** with `x-d3-edge`: `pass`, `block`, `fail-open`,
   `fail-closed`, or `disabled`.

Passed traffic then flows to the origin without touching our
infrastructure.

## Outcome reports (optional)

An adapter that proxies the response — as opposed to one that only
returns a verdict to a proxy — can report what the origin actually did,
after responding, without blocking anything:

```
POST https://edge-api.d3.com/v1/report
Authorization: Bearer <your adapter key>
```

Body: `requestId` (matching the decision), `ts` (epoch ms), `host`,
`path`, `method`, `mode` (the `x-d3-edge` value), and optionally
`status`, `originLatencyMs`, `contentType`, `contentLength`. Failures are
logged and swallowed — a report never affects a response.

Adapters that cannot defer work past the response (Cloudflare Snippets,
config-only proxies) simply skip this. Enforcement does not depend on it.

## Writing a new adapter

The shortest correct implementation in this repo is
[`cloudflare-snippet/snippet.js`](./cloudflare-snippet/snippet.js) — one
self-contained file, no imports, all of the above in about 160 lines.
Read it as the reference, then port. If you build one for a platform we
don't cover, we'd like to hear about it:
[hello@d3.com](mailto:hello@d3.com).
