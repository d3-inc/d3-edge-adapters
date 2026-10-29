-- web_bot_auth_verify.lua — D3 Edge enforcement for OpenResty.
--
-- Access-phase script: the nginx flavour of the Cloudflare adapter. Extracts
-- the RFC 9421 / Web Bot Auth headers (plus UA/IP) from the incoming request,
-- forwards a metadata payload to the policy endpoint, and enforces the
-- returned action (pass | block), failing open by default.
--
-- It also carries D3 Pay: a priced route is answered with the 402 or redirect
-- the endpoint hands back (PROTOCOL.md § Paid routes).
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
local POLICY_WORKER_URL   = os.getenv("POLICY_WORKER_URL")
local ADAPTER_KEY         = os.getenv("POLICY_ADAPTER_KEY")
local TIMEOUT_MS          = tonumber(os.getenv("POLICY_TIMEOUT_MS") or "150")
-- Seconds, not the hot path's milliseconds: settlement happens inside the call.
local PAYMENT_TIMEOUT_MS  = tonumber(os.getenv("POLICY_PAYMENT_TIMEOUT_MS") or "10000")
local FAIL_MODE           = os.getenv("FAIL_MODE") or "open" -- 'open' | 'closed'

-- Kill switch, same as every adapter: no endpoint means pure passthrough.
if not POLICY_WORKER_URL or POLICY_WORKER_URL == "" then
  ngx.header["x-d3-edge"] = "disabled"
  return
end

-- Headers forwarded to the policy worker — the same allowlist the other
-- adapters use (extractPayload in @d3-inc/d3-edge-core).
local FORWARDED_HEADERS = {
  "signature", "signature-input", "signature-agent", "user-agent",
  "content-digest",
  -- These four are how a navigating browser is told from an agent, which picks
  -- the 402 or the redirect.
  "accept", "sec-fetch-mode", "sec-fetch-dest", "upgrade-insecure-requests",
  "sec-purpose", "x-purpose", "purpose",
  -- x402 v2 renamed its header and a caller's version is unknowable here, so
  -- both names travel and the worker's decoder picks.
  "payment-signature", "x-payment", "payment-authorization",
}

-- Past these a value can never be meaningful, so it must not bloat the decision
-- POST — and for a payment header, past its cap is not a payment.
local HEADER_LENGTH_CAPS = {
  ["accept"]                    = 256,
  ["sec-fetch-mode"]            = 32,
  ["sec-fetch-dest"]            = 32,
  ["upgrade-insecure-requests"] = 32,
  ["payment-signature"]         = 4096,
  ["x-payment"]                 = 4096,
  ["payment-authorization"]     = 128,
}

local PAYMENT_HEADERS = {
  ["payment-signature"]     = 4096,
  ["x-payment"]             = 4096,
  ["payment-authorization"] = 128,
  ["d3pay-session"]         = 64,
}

-- `__Host-` pins the cookie to the site's origin: no Domain, Path=/, Secure.
local PAY_SESSION_COOKIE   = "__Host-d3pay"
-- The cookie's value travels under this name; the raw Cookie header never does.
local PAY_SESSION_HEADER   = "d3pay-session"
local PAY_SESSION_MAX_LEN  = 64
-- The browser check's pass (ADR 0057). Not a payment: it never buys the payment
-- budget, and it is stripped from the origin like one.
local PERSON_PASS_COOKIE   = "__Host-d3person"
local PERSON_PASS_HEADER   = "d3pay-person"
local PERSON_PASS_MAX_LEN  = 64
-- Where the credential rides for a caller with no cookie jar.
local PAY_HANDOFF_PARAM    = "d3pay_handoff"
-- The other two params of ours a visitor's navigation can carry back.
local PAY_PARAMS           = { PAY_HANDOFF_PARAM, "d3pay_check", "d3pay_browser" }
-- What this recipe does with the endpoint's answer (ADR 0068). Bump it only with
-- the behaviour: the worker reads it to decide whether a browser check can
-- finish here, and a copy that drops any of the three below must not claim 1.
local ADAPTER_SET          = 1

local function trim(s)
  local trimmed = string.gsub(s, "^%s*(.-)%s*$", "%1")
  return trimmed
end

-- ── D3 Pay credentials ───────────────────────────────────────────────────────
-- Presence, never a decode: this runs on the customer's own server, which must
-- not parse a payment.

-- Shape only; the signature over it is the worker's to check.
local function is_well_formed_handoff(token)
  if token == nil then return false end
  local id, sig = string.match(token, "^([A-Za-z0-9_-]+)%.([A-Za-z0-9_-]+)$")
  return id ~= nil and #id == 22 and #sig == 43
end

local function handoff_from_args(args)
  if args == nil or args == "" then return nil end
  for pair in string.gmatch(args, "([^&]+)") do
    local name, value = string.match(pair, "^([^=]*)=?(.*)$")
    if name == PAY_HANDOFF_PARAM then
      local decoded = ngx.unescape_uri(value)
      if is_well_formed_handoff(decoded) then return decoded end
      return nil
    end
  end

  return nil
end

-- Every param of ours, so none of them reaches the origin as a cache key or a
-- line in its access log. From the raw query string, not get_uri_args(): a
-- re-encoded table would reorder the upstream's parameters and re-escape its values.
local function strip_pay_params(args)
  if args == nil or args == "" then return args end
  local ours = {}
  for _, name in ipairs(PAY_PARAMS) do ours[name] = true end
  local kept = {}
  for pair in string.gmatch(args, "([^&]+)") do
    if not ours[string.match(pair, "^([^=]*)")] then kept[#kept + 1] = pair end
  end

  return table.concat(kept, "&")
end

local function read_cookie(cookie_header, cookie)
  if cookie_header == nil then return nil end
  for part in string.gmatch(cookie_header, "([^;]+)") do
    local name, value = string.match(part, "^%s*([^=]+)=(.*)$")
    if name ~= nil and trim(name) == cookie then return trim(value) end
  end

  return nil
end

-- Nil when ours were the only cookies, so the caller can clear the header.
local function strip_own_cookies(cookie_header)
  local prefixes = { PAY_SESSION_COOKIE .. "=", PERSON_PASS_COOKIE .. "=" }
  local kept = {}
  for part in string.gmatch(cookie_header, "([^;]+)") do
    local trimmed = trim(part)
    local ours = false
    for _, prefix in ipairs(prefixes) do
      if string.sub(trimmed, 1, #prefix) == prefix then ours = true end
    end

    if trimmed ~= "" and not ours then kept[#kept + 1] = trimmed end
  end

  if #kept == 0 then return nil end
  return table.concat(kept, "; ")
end

-- ── Gather request data ─────────────────────────────────────────────────────
local req_headers = ngx.req.get_headers()

local function header_value(name)
  local v = req_headers[name]
  -- get_headers() may return a table if a header appears multiple times.
  if type(v) == "table" then return v[#v] end
  return v
end

local fwd_headers = {}
for _, name in ipairs(FORWARDED_HEADERS) do
  local v = header_value(name)
  if v ~= nil then
    local cap = HEADER_LENGTH_CAPS[name]
    if cap == nil or #v <= cap then fwd_headers[name] = v end
  end
end

-- Our two cookies by name, each as a header of its own; the Cookie header itself
-- is the site's and stays there.
local cookie_header = header_value("cookie")
local session_cookie = read_cookie(cookie_header, PAY_SESSION_COOKIE)
if session_cookie ~= nil and #session_cookie > 0 and #session_cookie <= PAY_SESSION_MAX_LEN then
  fwd_headers[PAY_SESSION_HEADER] = session_cookie
end

local person_pass = read_cookie(cookie_header, PERSON_PASS_COOKIE)
if person_pass ~= nil and #person_pass > 0 and #person_pass <= PERSON_PASS_MAX_LEN then
  fwd_headers[PERSON_PASS_HEADER] = person_pass
end

-- All three places a credential rides. Miss one and a redemption gets the
-- hot-path budget, overruns it, and comes back a block.
local url_handoff = handoff_from_args(ngx.var.args)
local function presents_payment()
  for name, cap in pairs(PAYMENT_HEADERS) do
    local v = header_value(name)
    if v ~= nil and #v > 0 and #v <= cap then return true end
  end

  if fwd_headers[PAY_SESSION_HEADER] ~= nil then return true end
  return url_handoff ~= nil
end

local paying = presents_payment()

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
  adapterSet = ADAPTER_SET,
  ip        = ngx.var.remote_addr,           -- or parse X-Forwarded-For behind an LB
  method    = ngx.req.get_method(),          -- -> @method
  url       = ngx.var.request_uri,           -- raw path + query -> @path / @query
  host      = ngx.var.http_host,             -- Host header verbatim -> @authority
  timestamp = ngx.now(),                     -- seconds (float); informational
  headers   = fwd_headers,
}

-- ── Ask the policy worker for a decision ─────────────────────────────────────
local httpc = http.new()
httpc:set_timeout(paying and PAYMENT_TIMEOUT_MS or TIMEOUT_MS)

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

-- The page is priced and the charge may already have landed, so falling open
-- here would serve a paid page free.
local function payment_unavailable()
  ngx.log(ngx.ERR, "d3-edge: payment decision unavailable — failing closed")
  ngx.status = 502
  ngx.header["Content-Type"] = "application/json; charset=utf-8"
  ngx.header["Cache-Control"] = "no-store"
  ngx.header["x-d3-edge"] = "fail-closed"
  ngx.say('{"error":"payment_unavailable"}')
  return ngx.exit(502)
end

-- Everything of ours off the upstream request: the headers, our two cookies and
-- our query params. Defined here because the fail-open return below needs it
-- too — an endpoint we could not reach is no reason to hand the origin a
-- credential or a browser-check answer.
--
-- Unconditional, unlike the budget: an oversized value is not a payment, and it
-- still must not reach the upstream.
local function strip_credentials_from_upstream()
  for name, _ in pairs(PAYMENT_HEADERS) do
    ngx.req.clear_header(name)
  end
  ngx.req.clear_header(PERSON_PASS_HEADER)

  if session_cookie ~= nil or person_pass ~= nil then
    local kept = strip_own_cookies(cookie_header)
    if kept == nil then ngx.req.clear_header("Cookie") else ngx.req.set_header("Cookie", kept) end
  end

  -- $args, not ngx.req.set_uri_args(): that escapes what it is handed, so a query
  -- value already carrying a %XX would reach the upstream double-encoded. Both
  -- clear valid_unparsed_uri, which is what makes proxy_pass rebuild the target.
  if ngx.var.args ~= nil and string.find(ngx.var.args, "d3pay_", 1, true) ~= nil then
    ngx.var.args = strip_pay_params(ngx.var.args)
  end
end

-- Enforcement failure must never take the site down, unless opted into
-- fail-closed — or unless the request is paying.
local decision = res and res.status == 200 and cjson.decode(res.body) or nil
if type(decision) ~= "table" or (decision.action ~= "pass" and decision.action ~= "block") then
  ngx.log(ngx.ERR, "d3-edge: policy call failed: ", err or (res and res.status) or "bad decision")
  if paying then return payment_unavailable() end
  if FAIL_MODE == "closed" then return deny("fail-closed", nil) end
  strip_credentials_from_upstream()
  ngx.header["x-d3-edge"] = "fail-open"
  return
end

if decision.action == "block" then
  return deny("block", decision)
end

-- ── The payment answer ───────────────────────────────────────────────────────
-- A status, some headers and a string, copied: the script never learns what a
-- facilitator is, nor the payment protocol's own header names.

-- These values are provider and tenant authored, and this is the last place
-- before nginx's header table: a CR or LF through here is response splitting.
local function header_safe(name, value)
  if type(name) ~= "string" or type(value) ~= "string" then return false end
  if #name == 0 or #name > 64 or #value == 0 or #value > 8192 then return false end
  if string.find(name, "[^A-Za-z0-9!#$%%&'*+.%^_`|~%-]") ~= nil then return false end
  return string.find(value, "[^\032-\126]") == nil
end

-- Set in the access phase, so proxy_pass adds the upstream's own Set-Cookie
-- alongside ours instead of replacing it — the visitor keeps the site's session.
local function apply_payment_headers(headers)
  if type(headers) ~= "table" then return end
  for name, value in pairs(headers) do
    if header_safe(name, value) then ngx.header[name] = value end
  end
end

-- Narrowed here, not below: cjson decodes a JSON null to a userdata, and
-- indexing that inside the access phase is a 500 on every request.
local payment = type(decision.payment) == "table" and decision.payment or nil
if payment ~= nil and payment.status ~= nil then
  local status = tonumber(payment.status) or 502
  local redirect = status >= 300 and status <= 399
  local mode = (status == 402 and "payment-required")
    or (redirect and "payment-redirect")
    or "fail-closed"

  ngx.status = status
  -- A JSON type on a redirect misleads the client that follows it.
  if not redirect then ngx.header["Content-Type"] = "application/json; charset=utf-8" end
  ngx.header["Cache-Control"] = "no-store"
  apply_payment_headers(payment.headers)
  ngx.header["x-d3-edge"] = mode
  if not redirect and type(payment.body) == "string" then ngx.print(payment.body) end
  return ngx.exit(status)
end

-- ── Pass ─────────────────────────────────────────────────────────────────────
strip_credentials_from_upstream()

apply_payment_headers(payment and payment.headers)

-- Tag the response and expose the verdict to the upstream.
local verdict = decision.verdict or {}
ngx.header["x-d3-edge"] = "pass"
ngx.req.set_header("X-D3-Tier", verdict.tier or "")
ngx.req.set_header("X-D3-Identity", verdict.identity or "")
-- (fall through -> request continues to the upstream/content phase)
