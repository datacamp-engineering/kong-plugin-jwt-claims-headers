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

-- Rejections that are expected for real users (stale or broken tokens) and
-- would only add noise to the error log. Everything else points at Kong.
local EXPECTED_REJECTIONS = {
  malformed = true,
  missing_iss = true,
  expired = true,
  not_yet_valid = true,
}
local WARN_INTERVAL = 60
local last_warn_at = 0
local suppressed_warnings = 0

local function retrieve_token(request, conf)
  local uri_parameters = request.get_uri_args()

  for _, v in ipairs(conf.uri_param_names) do
    if uri_parameters[v] then
      return uri_parameters[v]
    end
  end

  local ngx_var = ngx.var
  for _, v in ipairs(conf.cookie_names) do
    local jwt_cookie = ngx_var["cookie_" .. v]
    if jwt_cookie and jwt_cookie ~= "" then
      return jwt_cookie
    end
  end

  local authorization_header = request.get_headers()["authorization"]
  if authorization_header then
    local iterator, iter_err = ngx_re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
    if not iterator then
      return nil, iter_err
    end

    local m, err = iterator()
    if err then
      return nil, err
    end

    if m and #m > 0 then
      return m[1]
    end
  end
end

-- Which request locations carry a token. Kong's jwt plugin rejects requests
-- that present more than one distinct token.
local function token_sources(request, conf)
  local sources = {}

  local uri_parameters = request.get_uri_args()
  for _, v in ipairs(conf.uri_param_names) do
    if uri_parameters[v] then
      sources[#sources + 1] = "uri"
      break
    end
  end

  local ngx_var = ngx.var
  for _, v in ipairs(conf.cookie_names) do
    local jwt_cookie = ngx_var["cookie_" .. v]
    if jwt_cookie and jwt_cookie ~= "" then
      sources[#sources + 1] = "cookie"
      break
    end
  end

  local authorization_header = request.get_headers()["authorization"]
  if type(authorization_header) == "string" and authorization_header:find("^%s*[Bb]earer%s") then
    sources[#sources + 1] = "header"
  end

  return table.concat(sources, ",")
end

local function cached_credential_state(value)
  if value == nil then
    return "absent"
  end
  -- mlcache stores negative lookups as an empty sentinel table in the LRU.
  if type(value) == "table" and next(value) == nil then
    return "negative"
  end
  return "present"
end

-- Explains why Kong's jwt plugin fell back to the anonymous consumer for a
-- token we could decode. Mirrors the checks the jwt plugin runs, and reports
-- what the credential cache holds both node-wide (shm) and in this worker's
-- own LRU (l1), so per-worker cache drift is visible in the access logs.
local function diagnose_rejection(jwt)
  local diag = {}

  if not jwt then
    diag.reason = "malformed"
    return diag
  end

  local claims = jwt.claims or {}
  local iss = claims.iss
  if type(iss) ~= "string" or iss == "" then
    diag.reason = "missing_iss"
    return diag
  end
  diag.iss = iss

  local now = ngx.time()
  if type(claims.exp) == "number" and claims.exp <= now then
    diag.reason = "expired"
    return diag
  end
  if type(claims.nbf) == "number" and claims.nbf > now then
    diag.reason = "not_yet_valid"
    return diag
  end

  local ok, cache_key = pcall(function()
    return kong.db.jwt_secrets:cache_key(iss)
  end)
  if not ok or not cache_key then
    diag.reason = "unknown"
    return diag
  end

  local credential
  local ttl, probe_err, shm_value = kong.cache:probe(cache_key)
  if probe_err then
    diag.shm = "error"
  elseif ttl == nil then
    diag.shm = "absent"
  else
    diag.shm = shm_value == nil and "negative" or "present"
    credential = shm_value
  end

  -- The LRU is an internal of lua-resty-mlcache; read it defensively.
  local lru_ok, lru_value = pcall(function()
    return kong.cache.mlcache.lru:get(cache_key)
  end)
  if lru_ok then
    diag.l1 = cached_credential_state(lru_value)
    if diag.l1 == "present" then
      credential = lru_value
    end
  else
    diag.l1 = "error"
  end

  if type(credential) ~= "table" then
    diag.reason = "credential_not_found"
    return diag
  end

  local alg = jwt.header and jwt.header.alg
  if alg ~= credential.algorithm then
    diag.reason = "algorithm_mismatch"
    return diag
  end

  local key = (type(alg) == "string" and alg:sub(1, 2) == "HS") and credential.secret
              or credential.rsa_public_key
  local verified_ok, verified = pcall(jwt.verify_signature, jwt, key)
  if not verified_ok or not verified then
    diag.reason = "signature_invalid"
    return diag
  end

  -- Our checks pass but Kong still rejected the token.
  diag.reason = "passes_local_checks"
  return diag
end

local function record_rejection(diag, sources)
  local worker = ngx.worker.id()

  kong.log.set_serialize_value("jwt_auth.result", "rejected")
  kong.log.set_serialize_value("jwt_auth.reason", diag.reason)
  kong.log.set_serialize_value("jwt_auth.worker", worker)
  kong.log.set_serialize_value("jwt_auth.sources", sources)
  if diag.iss then
    kong.log.set_serialize_value("jwt_auth.iss", diag.iss)
  end
  if diag.shm then
    kong.log.set_serialize_value("jwt_auth.shm", diag.shm)
  end
  if diag.l1 then
    kong.log.set_serialize_value("jwt_auth.l1", diag.l1)
  end

  if EXPECTED_REJECTIONS[diag.reason] then
    return
  end

  local now = ngx.now()
  if now - last_warn_at < WARN_INTERVAL then
    suppressed_warnings = suppressed_warnings + 1
    return
  end

  kong.log.warn("jwt plugin rejected a decodable token: reason=", diag.reason,
                " iss=", diag.iss or "-", " shm=", diag.shm or "-",
                " l1=", diag.l1 or "-", " sources=", sources,
                " worker=", worker, " suppressed=", suppressed_warnings)
  last_warn_at = now
  suppressed_warnings = 0
end

function JwtClaimsHeadersHandler:new()
  JwtClaimsHeadersHandler.super.new(self, "jwt-claims-headers")
end

function JwtClaimsHeadersHandler:access(conf)
  JwtClaimsHeadersHandler.super.access(self)
  local continue_on_error = conf.continue_on_error
  req_clear_header("X-user_id")
  req_clear_header("x-user-id")

  local token, err = retrieve_token(ngx.req, conf)
  
  local ttype = type(token)
  if ttype ~= "string" then
    if ttype == "nil" and continue_on_error then
      return
    end
  end

  if err and not continue_on_error then
    kong.log.err("error retrieving token: ", tostring(err))
    return kong.response.exit(HTTP_INTERNAL_SERVER_ERROR, {
      message = "An unexpected error occurred"
    })
  end

  if not token and not continue_on_error then
    return kong.response.exit(HTTP_UNAUTHORIZED, "Not authorized")
  end

  local jwt, err = jwt_decoder:new(token)
  if err and not continue_on_error then
    kong.log.err("error decoding token: ", tostring(err))
    return kong.response.exit(HTTP_INTERNAL_SERVER_ERROR, {
      message = "An unexpected error occurred"
    })
  end

  ngx.ctx.jwt_claims = {}
  kong.ctx.shared.jwt_claims = {}
  kong.ctx.shared.jwt_token = token

  local anonymous_consumer = kong.request.get_headers()[constants.HEADERS.ANONYMOUS]
  -- Kong JWT plugin makes sure this header can't be spoofed: https://github.com/Kong/kong/blob/ea40d9bc8af59d4d1623eb5464b3b996f5bd007d/kong/plugins/jwt/handler.lua#L111
  if anonymous_consumer == "true" then
    record_rejection(diagnose_rejection(not err and jwt or nil), token_sources(ngx.req, conf))
    return
  end

  if kong.client.get_credential() then
    kong.log.set_serialize_value("jwt_auth.result", "authenticated")
    kong.log.set_serialize_value("jwt_auth.worker", ngx.worker.id())
  end

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
