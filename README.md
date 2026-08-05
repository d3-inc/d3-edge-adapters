# D3 Edge adapters

Install adapters and copy-paste recipes for [D3 Edge](https://ai.d3.com)
bot-auth enforcement. Each directory is self-contained, with its own
README covering install, configuration, and behavior.

Every adapter does the same job in front of your site: extract request
metadata, ask your D3 Edge policy endpoint for a decision, then pass the
request through or answer `403` — failing open if the call errors or
times out, so an outage on our side never takes your site down.

| Directory                                    | What it is                                                                       |
| -------------------------------------------- | -------------------------------------------------------------------------------- |
| [`cloudflare-snippet/`](./cloudflare-snippet) | A single pasted file for Cloudflare zones — no Worker deploy (paid plans). Traffic sampling built in |
| [`cloudflare-worker/`](./cloudflare-worker)   | Standalone Worker template fronting a site hosted outside Cloudflare             |
| [`caddy/`](./caddy)                           | Config-only recipe for Caddy's built-in `forward_auth` — no plugin, no build     |
| [`nginx/`](./nginx)                           | Access-phase Lua script for OpenResty / nginx with the Lua module                |
| [`nginx-auth-request/`](./nginx-auth-request) | Config-only recipe for stock nginx via `auth_request` — no Lua required          |

All of them speak one contract, specified in
[`PROTOCOL.md`](./PROTOCOL.md): the decision payload, the response, the
`Content-Digest` rule, and the behavior — fail-open, timeout budget,
`403` shape — an adapter has to get right. Read it to write an adapter
for a platform we don't cover yet, or to see exactly what leaves your
infrastructure.

The npm SDKs —
[`@d3-inc/d3-edge-cloudflare-adapter`](https://www.npmjs.com/package/@d3-inc/d3-edge-cloudflare-adapter)
(wrap an existing Worker, or deploy standalone) and
[`@d3-inc/d3-edge-vercel-middleware`](https://www.npmjs.com/package/@d3-inc/d3-edge-vercel-middleware) —
are published from the main D3 Edge repo; this repo holds the adapters
that aren't npm packages.

Full documentation: [ai.d3.com/docs](https://ai.d3.com/docs). Questions:
[hello@d3.com](mailto:hello@d3.com).

## Tests

```sh
npm install
npm test
```

## License

Apache-2.0
