# D3 Edge for nginx (`auth_request`)

[D3 Edge](https://ai.d3.com) enforcement through nginx's standard
[`auth_request`](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html)
module — pure config, no Lua, no OpenResty, works on any distro nginx.
Per request nginx sends a small subrequest to the D3 Edge decision
endpoint and reads the status code: `200` continues to your site, `403`
blocks.

This is the forward-auth dialect of [the decision
protocol](../PROTOCOL.md#the-forward-auth-dialect). If you run
OpenResty (or Kong/APISIX), the [Lua adapter](../nginx) is the richer
install: it can hash request bodies and hand the verdict to your
upstream as request headers. This recipe trades that for zero
dependencies.

## Requirements

nginx built with `http_auth_request_module` — included in every distro
package (`nginx -V 2>&1 | grep auth_request` to confirm).

## Install

1. Merge [`d3-edge.conf`](./d3-edge.conf) into your server block: the
   `upstream` once, the three `location` pieces per server you want
   covered.
2. Create an adapter key at
   [dashboard.d3.com/keys](https://dashboard.d3.com/keys) and replace
   `d3_k_REPLACE_ME`. nginx config can't read environment variables, so
   the key lives in the file — it is org-scoped and grants no reads;
   restrict the file as you would any config with a credential.
3. `nginx -t && nginx -s reload`.

## How fail-open works (don't trim these lines)

Enforcement breaking must never take your site down. Three details in
the recipe carry that, and each one is load-bearing:

- **`error_page 500 = @d3_edge_failopen`** — a failed subrequest
  (timeout, connection refused, 5xx from us) surfaces as an
  nginx-generated 500, which `error_page` reroutes to the fallback.
  Your app's own 500s are not nginx-generated and pass through
  untouched.
- **`auth_request off` inside the fallback** — without it the fallback
  re-runs the check and loops.
- **The 500 ms timeouts** — a hung endpoint must degrade like a down
  one, inside the same budget every D3 Edge adapter uses.

Two failure modes stay server-side by design: a dead or revoked adapter
key answers `200 fail-open` (never `401` — nginx couldn't tell it apart
from a block), tagged `x-d3-reason` and worth alerting on.

## What leaves your infrastructure

The subrequest inherits the visitor's request headers. The recipe
clears what we must never receive (`Cookie`, `Authorization`,
`Proxy-Authorization`) and pins what we must be able to trust
(`x-d3-real-ip`, the adapter key, no client-set `x-d3-*`). Note this is
remove-what-you-name: an unusual header the recipe doesn't clear would
still reach us.

No request body is ever sent — `auth_request` runs before nginx reads
the client body, so there is nothing to forward. The one consequence:
signed `POST`/`PUT` requests get a capped verdict (`claimed`, reason
`body-unattested`) because nothing could check the body against its
signed digest. `GET`/`HEAD` — nearly all agent traffic — are
unaffected. If body attestation matters to you, use the [Lua
adapter](../nginx).

## Notes

- A blocked visitor gets nginx's own `403` page — `auth_request`
  discards the deny response's JSON body. To serve the machine-readable
  body other adapters return, add `error_page 403` handling of your
  own.
- `auth_request` runs per request, including static assets. Scope the
  `auth_request` directive to the locations you care about, or start
  with signed traffic only by wrapping it in a `map` on
  `$http_signature`.
- Verify server-side: `curl -sI -H 'signature-input: x'
  https://example.com/` and watch the request appear in your
  [dashboard](https://dashboard.d3.com) — a passed response looks
  exactly like your site without the recipe.
