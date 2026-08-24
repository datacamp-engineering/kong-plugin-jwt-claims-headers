local BasePlugin = require "kong.plugins.base_plugin"
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local constants = require "kong.constants"

local req_set_header = ngx.req.set_header
local ngx_re_gmatch = ngx.re.gmatch
local req_clear_header = ngx.req.clear_header

local HTTP_INTERNAL_SERVER_ERROR = 500
local HTTP_UNAUTHORIZED = 401
local JwtClaimsHeadersHandler = BasePlugin:extend()
-- See https://docs.konghq.com/2.0.x/plugin-development/custom-logic/#plugins-execution-order
-- Must execute before the request-transformer plugin because it sets variables in the shared context
JwtClaimsHeadersHandler.PRIORITY = 970

-- Returns every candidate token present on the request, in priority order
-- (uri param -> cookie -> Authorization header). Previously this plugin
-- returned only the *first* candidate found and gave up entirely if it
-- failed to decode, even when a second, valid credential was present in a
-- lower-priority slot (e.g. valid _dct cookie + invalid Bearer token, or
-- vice-versa). That produced inconsistent auth headers downstream: see
-- INF-5541.
--
-- ngx.req.get_uri_args()/get_headers() return a table (array) instead of a
-- string when a name is repeated (e.g. ?jwt=a&jwt=b, or two Authorization
-- headers). jwt_decoder:new() raises a hard Lua error -- not a graceful
-- nil, err -- when given a non-string, so any such value must be reduced to
-- its first element (matching Kong's own single-value convention) or
-- dropped before it ever reaches a candidate list or a decode call.
local function first_value(value)
  if type(value) == "table" then
    return value[1]
  end
  return value
end

local function retrieve_candidate_tokens(request, conf)
  local candidates = {}

  local uri_parameters = request.get_uri_args()
  for _, v in ipairs(conf.uri_param_names) do
    local candidate = first_value(uri_parameters[v])
    if type(candidate) == "string" and candidate ~= "" then
      table.insert(candidates, candidate)
    end
  end

  local ngx_var = ngx.var
  for _, v in ipairs(conf.cookie_names) do
    local jwt_cookie = ngx_var["cookie_" .. v]
    if jwt_cookie and jwt_cookie ~= "" then
      table.insert(candidates, jwt_cookie)
    end
  end

  local authorization_header = first_value(request.get_headers()["authorization"])
  if type(authorization_header) == "string" then
    local iterator, iter_err = ngx_re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
    if iterator then
      local m, err = iterator()
      if not err and m and #m > 0 then
        table.insert(candidates, m[1])
      end
    end
  end

  return candidates
end

-- Mirrors kong-keycloak-short-session-validator's make_anonymous(): explicitly
-- marks the request as anonymous rather than leaving x-user-id blank while
-- x-anonymous-consumer/x-consumer-username stay whatever an upstream auth
-- plugin (e.g. the native `jwt` plugin) already set them to. Per the
-- documented header contract (PRODENG "Add JWT Auth to my kong service"),
-- x-user-id must only ever be set when the consumer is not anonymous.
local function make_anonymous()
  kong.service.request.set_header(constants.HEADERS.ANONYMOUS, "true")
  kong.service.request.set_header(constants.HEADERS.CONSUMER_USERNAME, "anonymous")
  req_clear_header("X-user_id")
  req_clear_header("x-user-id")
end

function JwtClaimsHeadersHandler:new()
  JwtClaimsHeadersHandler.super.new(self, "jwt-claims-headers")
end

function JwtClaimsHeadersHandler:access(conf)
  JwtClaimsHeadersHandler.super.access(self)
  local continue_on_error = conf.continue_on_error
  req_clear_header("X-user_id")
  req_clear_header("x-user-id")

  local anonymous_consumer = kong.request.get_headers()[constants.HEADERS.ANONYMOUS]
  -- Kong JWT plugin makes sure this header can't be spoofed: https://github.com/Kong/kong/blob/ea40d9bc8af59d4d1623eb5464b3b996f5bd007d/kong/plugins/jwt/handler.lua#L111
  if anonymous_consumer == "true" then
    return
  end

  -- Prefer the exact token an upstream auth plugin (e.g. Kong's native
  -- `jwt` plugin) already cryptographically verified -- it stores it in
  -- kong.ctx.shared.authenticated_jwt_token on success. This plugin's own
  -- retrieve_candidate_tokens()/jwt_decoder:new() never verifies a
  -- signature, only structure, so independently re-deriving "the" token via
  -- uri-param/cookie/header priority order can pick a *different*,
  -- unverified credential from the one that was actually authenticated --
  -- e.g. a valid _dct cookie plus an invalid (bad signature/expired) Bearer
  -- token, or vice-versa, both "decode" fine but only one was verified.
  -- See INF-5541.
  local token = kong.ctx.shared.authenticated_jwt_token

  if not token then
    -- No upstream plugin already authenticated a token for this request
    -- (e.g. jwt-claims-headers used standalone, without Kong's native `jwt`
    -- plugin on the route) -- fall back to retrieving one ourselves, same
    -- as before.
    local candidates = retrieve_candidate_tokens(ngx.req, conf)

    if #candidates == 0 then
      if continue_on_error then
        return
      end
      return kong.response.exit(HTTP_UNAUTHORIZED, "Not authorized")
    end

    for _, candidate in ipairs(candidates) do
      local decoded, decode_err = jwt_decoder:new(candidate)
      if decoded and not decode_err then
        token = candidate
        break
      end
    end

    if not token then
      if continue_on_error then
        -- Every presented credential failed to even decode structurally.
        -- None of them can be trusted for claims extraction, so make the
        -- request explicitly anonymous instead of leaving x-user-id blank
        -- while a different (shared) consumer may still be set upstream.
        make_anonymous()
        return
      end
      return kong.response.exit(HTTP_INTERNAL_SERVER_ERROR, {
        message = "An unexpected error occurred"
      })
    end
  end

  local jwt, err = jwt_decoder:new(token)
  if err then
    if continue_on_error then
      make_anonymous()
      return
    end
    return kong.response.exit(HTTP_INTERNAL_SERVER_ERROR, {
      message = "An unexpected error occurred"
    })
  end

  ngx.ctx.jwt_claims = {}
  kong.ctx.shared.jwt_claims = {}
  kong.ctx.shared.jwt_token = token

  local claims = jwt.claims
  for claim_key,claim_value in pairs(claims) do
    for _,claim_pattern in pairs(conf.claims_to_include) do
      if string.match(claim_key, "^"..claim_pattern.."$") then
        ngx.ctx.jwt_claims[claim_key] = claim_value
        kong.ctx.shared.jwt_claims[claim_key] = claim_value
        req_set_header("X-"..claim_key, claim_value)
        if claim_key == "user_id" then
          req_set_header("x-user-id", claim_value)
        end
      end
    end
  end
end

return JwtClaimsHeadersHandler
