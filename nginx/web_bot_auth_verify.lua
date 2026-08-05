-- web_bot_auth_verify.lua — D3 Edge enforcement for OpenResty.
--
-- Access-phase script: the nginx flavour of the Cloudflare adapter. Extracts
-- the RFC 9421 / Web Bot Auth headers (plus UA/IP) from the incoming request,
-- forwards a metadata payload to the policy endpoint, and enforces the
-- returned action (pass | block), failing open by default.
--
-- Unlike the Cloudflare adapter, on pass this one also exposes the verdict to
-- the upstream via X-D3-Tier / X-D3-Identity request headers.
--
-- Requires OpenResty (ngx_http_lua_module) + lua-resty-http:
--   opm get ledgetech/lua-resty-http      # or luarocks install lua-resty-http
--
-- Wire it up per-location with:  access_by_lua_file .../web_bot_auth_verify.lua;
-- See nginx.conf and README.md in this directory; docs:
-- https://ai.d3.com/docs/sdks/nginx

local http   = require "resty.http"
local cjson  = require "cjson.safe"
local sha256 = require "resty.sha256"

-- ── Configuration (each var needs an `env` line in nginx.conf's main context) ─
local POLICY_WORKER_URL = os.getenv("POLICY_WORKER_URL")
local ADAPTER_KEY       = os.getenv("POLICY_ADAPTER_KEY")
local TIMEOUT_MS        = tonumber(os.getenv("POLICY_TIMEOUT_MS") or "150")
local FAIL_MODE         = os.getenv("FAIL_MODE") or "open" -- 'open' | 'closed'

-- Kill switch, same as every adapter: no endpoint means pure passthrough.
if not POLICY_WORKER_URL or POLICY_WORKER_URL == "" then
  ngx.header["x-d3-edge"] = "disabled"
  return
end

-- Headers forwarded to the policy worker — the same allowlist the other
-- adapters use (extractPayload in @d3-inc/d3-edge-core).
local FORWARDED_HEADERS = {
  "signature", "signature-input", "signature-agent", "user-agent",
  "content-digest", "sec-purpose", "x-purpose", "purpose",
}

-- ── Gather request data ─────────────────────────────────────────────────────
local req_headers = ngx.req.get_headers()

local fwd_headers = {}
for _, name in ipairs(FORWARDED_HEADERS) do
  local v = req_headers[name]
  if v ~= nil then
    -- get_headers() may return a table if a header appears multiple times.
    fwd_headers[name] = type(v) == "table" and v[#v] or v
  end
end

-- Overwrite content-digest with the real body's digest — never forward the
-- client's claim, or a signature over a forged digest gets a "proven" verdict
-- for a body that was never authenticated. Recompute whenever there's a body
-- OR a claimed digest; never add one to a request that has neither (that would
-- fail body-less signed requests). Mirrors the Cloudflare adapter (extract.ts).
ngx.req.read_body()
local body_data = ngx.req.get_body_data()
if body_data == nil then
  -- Body spilled to disk (> client_body_buffer_size): read it back.
  local body_file = ngx.req.get_body_file()
  if body_file ~= nil then
    local f = io.open(body_file, "rb")
    if f ~= nil then
      body_data = f:read("*a")
      f:close()
    end
  end
end
body_data = body_data or ""
if #body_data > 0 or fwd_headers["content-digest"] ~= nil then
  local digest = sha256:new()
  digest:update(body_data)
  fwd_headers["content-digest"] = "sha-256=:" .. ngx.encode_base64(digest:final()) .. ":"
end

local payload = {
  requestId = ngx.var.request_id,            -- nginx's per-request id (32 hex chars)
  ip        = ngx.var.remote_addr,           -- or parse X-Forwarded-For behind an LB
  method    = ngx.req.get_method(),          -- -> @method
  url       = ngx.var.request_uri,           -- raw path + query -> @path / @query
  host      = ngx.var.http_host,             -- Host header verbatim -> @authority
  timestamp = ngx.now(),                     -- seconds (float); informational
  headers   = fwd_headers,
}

-- ── Ask the policy worker for a decision ─────────────────────────────────────
local httpc = http.new()
httpc:set_timeout(TIMEOUT_MS)

local res, err = httpc:request_uri(POLICY_WORKER_URL, {
  method     = "POST",
  body       = cjson.encode(payload),
  ssl_verify = true,
  headers    = {
    ["Content-Type"]  = "application/json",
    ["Authorization"] = ADAPTER_KEY and ("Bearer " .. ADAPTER_KEY) or nil,
  },
})

local function deny(mode, decision)
  local verdict = decision and decision.verdict or {}
  ngx.log(ngx.WARN, "d3-edge: blocked (", decision and decision.ruleId or mode, ")")
  ngx.status = ngx.HTTP_FORBIDDEN
  ngx.header["Content-Type"] = "application/json; charset=utf-8"
  ngx.header["x-d3-edge"] = mode
  ngx.say(cjson.encode({
    blocked  = true,
    ruleId   = decision and decision.ruleId or nil,
    tier     = verdict.tier,
    identity = verdict.identity,
  }))
  return ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- Enforcement failure must never take the site down, unless opted into
-- fail-closed.
local decision = res and res.status == 200 and cjson.decode(res.body) or nil
if type(decision) ~= "table" or (decision.action ~= "pass" and decision.action ~= "block") then
  ngx.log(ngx.ERR, "d3-edge: policy call failed: ", err or (res and res.status) or "bad decision")
  if FAIL_MODE == "closed" then return deny("fail-closed", nil) end
  ngx.header["x-d3-edge"] = "fail-open"
  return
end

if decision.action == "block" then
  return deny("block", decision)
end

-- Pass: tag the response and expose the verdict to the upstream.
local verdict = decision.verdict or {}
ngx.header["x-d3-edge"] = "pass"
ngx.req.set_header("X-D3-Tier", verdict.tier or "")
ngx.req.set_header("X-D3-Identity", verdict.identity or "")
-- (fall through -> request continues to the upstream/content phase)
