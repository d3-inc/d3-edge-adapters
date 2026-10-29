# D3 Edge for nginx (OpenResty)

[D3 Edge](https://ai.d3.com) enforcement as a small Lua script in
nginx's access phase, before your site sees the request. Per request it
extracts metadata, asks the decision service for a decision, then lets
the request continue or returns a `403`. It holds no state, and if the
decision call errors or exceeds its budget your site serves exactly as
before.

One thing this install can do that the others can't: on pass it hands
the verdict to your upstream as `X-D3-Tier` and `X-D3-Identity` request
headers, so your application can make its own calls — serve a lighter
page to a crawler, skip analytics for bots — with the identity already
proven at the edge.

## Requirements

nginx with Lua support — that means [OpenResty](https://openresty.org/),
or a build with `ngx_http_lua_module` (Kong and APISIX ship it). Plus
one library:

```sh
opm get ledgetech/lua-resty-http
```

## Install

1. Save [`web_bot_auth_verify.lua`](./web_bot_auth_verify.lua) as
   `/etc/nginx/lua/web_bot_auth_verify.lua`.
2. Add the config from [`nginx.conf`](./nginx.conf): the `env` lines at
   the very top of your `nginx.conf`, the `http {}` settings, and one
   `access_by_lua_file` line in each location you want protected.
3. Set the environment variables where nginx starts (systemd unit,
   container env), with your API key — created at
   [dashboard.d3.com/keys](https://dashboard.d3.com/keys) — in
   `DNA_API_KEY`. That is the only variable DNA needs. Reload nginx.

Check it's live with `curl -sI https://www.example.com/` — every
response carries an `x-d3-edge` header once it is.

## Configuration

The script reads these from the environment nginx starts with — each
one needs its `env` line in the main context, or nginx hides it from
Lua:

| Variable                 | Type                 | Default                               | What it does                                                                  |
| ------------------------ | -------------------- | ------------------------------------- | ----------------------------------------------------------------------------- |
| `DNA_API_KEY`            | string               | unset                                 | Your org's key, bearer for the decision call. **Unset means pure passthrough**: the script does nothing. |
| `DNA_ENABLED`            | `"false"`            | unset                                 | `false` turns DNA off without removing the key.                               |
| `DNA_FAIL_MODE`          | `"open" \| "closed"` | `open`                                | `open`: pass traffic when the call fails. `closed`: block instead.            |
| `DNA_TIMEOUT_MS`         | number (ms)          | `150`                                 | Hard budget for the decision call.                                            |
| `DNA_PAYMENT_TIMEOUT_MS` | number (ms)          | `10000`                               | Budget for a request presenting a payment — settlement happens inside it.     |
| `DNA_ENDPOINT`           | string (URL)         | `https://edge-api.d3.com/v1/decision` | Decision endpoint. Leave unset unless we give you another.                    |

### Earlier names

An install set up with the earlier names keeps working, and a `DNA_` name
wins when both are set. With the earlier names, `POLICY_WORKER_URL` is still
what switches DNA on.

| Earlier name                | Now                          |
| --------------------------- | ---------------------------- |
| `POLICY_ADAPTER_KEY`        | `DNA_API_KEY`                |
| `POLICY_WORKER_URL`         | `DNA_ENDPOINT`, now optional |
| `POLICY_TIMEOUT_MS`         | `DNA_TIMEOUT_MS`             |
| `POLICY_PAYMENT_TIMEOUT_MS` | `DNA_PAYMENT_TIMEOUT_MS`     |
| `FAIL_MODE`                 | `DNA_FAIL_MODE`              |

To move over, take this directory's script and `env` lines, rename each
variable, and drop `POLICY_WORKER_URL`.

## Response shape

Every response carries an `x-d3-edge` header: `disabled`, `pass`,
`block`, `fail-open`, or `fail-closed`. A blocked request gets a `403`
with a JSON body:

```json
{ "blocked": true, "ruleId": "…", "tier": "…", "identity": "…" }
```

On pass, your upstream additionally receives the verdict as `X-D3-Tier`
and `X-D3-Identity` request headers — set by the script on every pass,
so a client can't spoof them past it.

## Paid routes (D3 Pay)

This install carries [D3 Pay](../PROTOCOL.md#paid-routes). If you price
a route in the dashboard, the script answers an unpaid request with the
`402` the decision endpoint hands back — or a `302` to the pay app when
a browser is navigating — and serves the page once the visitor's agent
presents a credential:

- **The credential is forwarded, never parsed.** A `__Host-d3pay`
  cookie travels to the decision endpoint as a `d3pay-session` header,
  on its own; the rest of the visitor's `Cookie` header stays on your
  server. A `Payment-Authorization` header or a `?d3pay_handoff=` on the
  URL works the same way for an agent with no cookie jar.
- **A paying request gets its own budget.** `DNA_PAYMENT_TIMEOUT_MS`
  (10 s) rather than `DNA_TIMEOUT_MS`, because settlement happens
  inside that call.
- **A paying request never falls open.** Whatever `DNA_FAIL_MODE` says, a
  failed decision call on a request carrying a credential answers `502
  {"error":"payment_unavailable"}`. The page is priced and the charge may
  already have landed; serving it free is the one wrong answer.
- **Your upstream never sees a credential.** The payment headers are
  cleared, our cookie is taken out of `Cookie` (yours are left alone),
  and `d3pay_handoff` is removed from the query string before the
  request is proxied. The receipt and the session cookie ride back on
  your upstream's own response.

Nothing changes for a site with no priced routes: the decision endpoint
sends no payment instruction and the script never takes the path.
