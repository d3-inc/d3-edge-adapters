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
   `POLICY_ADAPTER_KEY`. Reload nginx.

Check it's live with `curl -sI https://www.example.com/` — every
response carries an `x-d3-edge` header once it is.

## Configuration

The script reads these from the environment nginx starts with — each
one needs its `env` line in the main context, or nginx hides it from
Lua:

| Variable             | Type                 | Default | What it does                                                                  |
| -------------------- | -------------------- | ------- | ----------------------------------------------------------------------------- |
| `POLICY_WORKER_URL`  | string (URL)         | unset   | Decision endpoint. **Unset means pure passthrough**: the script does nothing. |
| `POLICY_ADAPTER_KEY` | string               | unset   | Your org's key, bearer for the decision call.                                 |
| `POLICY_TIMEOUT_MS`  | number (ms)          | `150`   | Hard budget for the decision call.                                            |
| `FAIL_MODE`          | `"open" \| "closed"` | `open`  | `open`: pass traffic when the call fails. `closed`: block instead.            |

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
