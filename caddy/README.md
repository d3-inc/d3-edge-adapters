# D3 Edge for Caddy (`forward_auth`)

[D3 Edge](https://ai.d3.com) enforcement through Caddy's built-in
[`forward_auth`](https://caddyserver.com/docs/caddyfile/directives/forward_auth)
directive — pure config, no plugin, no custom build. Per request Caddy
sends a small side-request to the D3 Edge decision endpoint and reads
the status code: `200` continues to your site, `403` is returned to the
visitor as-is (JSON body included).

This is the forward-auth dialect of [the decision
protocol](../PROTOCOL.md#the-forward-auth-dialect): the original method
and URL ride in `X-Forwarded-*` headers, the client's own headers —
including Web Bot Auth signatures — are copied along, and there is no
adapter code anywhere.

## Requirements

Stock Caddy 2. Nothing else.

## Install

1. Copy both blocks from [`Caddyfile`](./Caddyfile) into your Caddyfile:
   the decision gateway once, the `forward_auth` block into each site
   you want covered.
2. Create an adapter key at
   [dashboard.d3.com/keys](https://dashboard.d3.com/keys) and set it as
   `D3_EDGE_ADAPTER_KEY` in Caddy's environment.
3. Reload: `caddy reload`.

## How fail-open works (read before changing the gateway)

Enforcement breaking must never take your site down — but `forward_auth`
returns any upstream error straight to the visitor, which is fail-
*closed*. The recipe's local gateway hop is what inverts that:
`forward_auth` talks to `127.0.0.1:8113`, which proxies to the real
endpoint with a hard 500 ms budget, and its `handle_errors` block turns
a dead, unreachable, or hung endpoint into `200` + `x-d3-edge:
fail-open`. Two failure modes remain server-side by design: a dead or
revoked adapter key also answers `200 fail-open` (never `401` — the
proxy couldn't tell it apart from a block), tagged with an
`x-d3-reason` header and worth alerting on.

The gateway runs in the same Caddy process, so there is no separate
service to keep alive.

## What leaves your infrastructure

`forward_auth` copies the visitor's request headers onto the
side-request. The recipe strips what we must never receive (`Cookie`,
`Authorization`, `Proxy-Authorization`) and pins what we must be able to
trust (`x-d3-real-ip`, the adapter key, no client-set `x-d3-*`). Note this
is remove-what-you-name: an unusual header the recipe doesn't strip
would still reach us. If you need keep-only-what-you-name semantics, use
a proxy with a true allowlist (Envoy's `headersToExtAuth`).

No request body is ever sent — Caddy rewrites the side-request to a
body-less `GET`. The one consequence: signed `POST`/`PUT` requests get a
capped verdict (`claimed`, reason `body-unattested`) because nothing
could check the body against its signed digest. `GET`/`HEAD` — nearly
all agent traffic — are unaffected.

## Scoping and ramp-up

`forward_auth` takes a matcher like any Caddy directive. To start with
only signed agent traffic (tiny volume, the traffic D3 Edge exists for):

```caddyfile
	@signed header Signature *
	forward_auth @signed 127.0.0.1:8113 {
		# ...same block as above
	}
```

Widen the matcher when you're ready for more.

## Verifying it works

A passed response looks exactly like your site without the recipe —
Caddy doesn't copy the side-request's headers onto what the visitor
gets. Check server-side instead: send

```sh
curl -sI -H 'signature-input: x' https://example.com/
```

and watch the request appear in your [D3
dashboard](https://dashboard.d3.com). A blocked request is visible from
outside: `403` with the `x-d3-edge: block` header and a JSON body.
