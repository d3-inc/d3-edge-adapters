# D3 Edge worker

Puts [D3 Edge](https://ai.d3.com) in front of a site hosted outside
Cloudflare — nginx, a VPS, another cloud. On every request the worker
asks your D3 Edge policy for a decision, then passes the request on to
your site or answers `403`. If the check errors or times out, traffic
passes: an outage on our side never takes your site down.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/d3-inc/d3-edge-worker-template)

The deploy flow asks for one secret, `POLICY_ADAPTER_KEY` — create the
key at [dashboard.d3.com/keys](https://dashboard.d3.com/keys)
first.

## After deploying: connect your site

The worker starts disconnected and serves nothing until you attach it.
In the Cloudflare dashboard: **Workers & Pages → your worker → Settings
→ Domains & Routes**, add a route like `www.example.com/*`. Your DNS
record stays exactly what it is; allowed traffic flows on to your site
like before.

Check it's live with `curl -sI https://www.example.com/` — every
response carries an `x-d3-edge` header once it is.

## Turning it off

Remove the route, or unset `POLICY_WORKER_URL`, and the worker passes
everything untouched. Your site never depends on D3 Edge to serve.

## Configuration

Every variable the worker reads — timeout budget, fail mode, origin
overrides — is in the [configuration
reference](https://ai.d3.com/docs/sdks/cloudflare#configuration-reference).

## About this template

This directory is the canonical copy;
[`d3-edge-worker-template`](https://github.com/d3-inc/d3-edge-worker-template)
mirrors it so the deploy button has a repo of its own to clone. Issues
are welcome; for anything else, write to
[hello@d3.com](mailto:hello@d3.com).
