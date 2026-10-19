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

-- Rejection reasons that point at Kong itself rather than at the token or
-- the client: stale per-worker cache entries, a credential whose consumer
-- cannot be loaded, or a token that passes every check we can replicate.
-- These are flagged with jwt_auth.kong_side and logged as a warning.
local KONG_SIDE_REJECTIONS = {
  credential_stale_in_worker = true,
  consumer_stale_in_worker = true,
  consumer_not_found = true,
  passes_local_checks = true,
}
local WARN_INTERVAL = 60
local MAX_ISS_LENGTH = 128
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

local function bearer_token(authorization_header)
  if type(authorization_header) ~= "string" then
    return nil
  end
  local m = ngx.re.match(authorization_header, "\\s*[Bb]earer\\s+(.+)", "jo")
  return m and m[1] or nil
end

-- Distinct tokens and the request locations carrying them. Kong's jwt plugin
-- rejects a request that presents more than one distinct token.
local function collect_tokens(request, conf)
  local sources, distinct, count = {}, {}, 0
  local function add(source, token)
    if type(token) ~= "string" or token == "" then
      return
    end
    sources[#sources + 1] = source
    if not distinct[token] then
      distinct[token] = true
      count = count + 1
    end
  end

  local uri_parameters = request.get_uri_args()
  for _, v in ipairs(conf.uri_param_names) do
    add("uri", uri_parameters[v])
  end

  local ngx_var = ngx.var
  for _, v in ipairs(conf.cookie_names) do
    add("cookie", ngx_var["cookie_" .. v])
  end

  add("header", bearer_token(request.get_headers()["authorization"]))

  return table.concat(sources, ","), count
end

local function sanitize(value)
  return (value:sub(1, MAX_ISS_LENGTH):gsub("%c", "?"))
end

-- What the node-wide cache (shm) and this worker's own LRU (l1) hold for a
-- key. "negative" means a cached "not found".
local function probe_cache(cache_key)
  local shm, l1, value
  local ttl, err, shm_value = kong.cache:probe(cache_key)
  if err then
    shm = "error"
  elseif ttl == nil then
    shm = "absent"
  elseif shm_value == nil then
    shm = "negative"
  else
    shm = "present"
    value = shm_value
  end

  -- The LRU is an internal of lua-resty-mlcache; read it defensively.
  -- mlcache stores negative lookups in the LRU as an empty sentinel table.
  local ok, lru_value = pcall(function()
    return kong.cache.mlcache.lru:get(cache_key)
  end)
  if not ok then
    l1 = "error"
  elseif lru_value == nil then
    l1 = "absent"
  elseif type(lru_value) == "table" and next(lru_value) == nil then
    l1 = "negative"
  else
    l1 = "present"
    value = lru_value
  end

  return shm, l1, value
end

-- Explains why Kong's jwt plugin fell back to the anonymous consumer for a
-- token we could decode, by replaying its checks in the same order: token
-- count, issuer, credential, algorithm, signature, consumer, then the
-- registered claims. Credential and consumer lookups report both cache
-- layers, so per-worker cache drift is visible in the access logs.
local function diagnose_rejection(jwt, token_count)
  local diag = {}

  if token_count > 1 then
    diag.reason = "multiple_tokens"
    return diag
  end

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
  diag.iss = sanitize(iss)

  local credential_key = kong.db.jwt_secrets:cache_key(iss)
  local credential
  diag.shm, diag.l1, credential = probe_cache(credential_key)
  if diag.l1 == "negative" and diag.shm == "present" then
    diag.reason = "credential_stale_in_worker"
    return diag
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

  local consumer_id = type(credential.consumer) == "table" and credential.consumer.id
  if consumer_id then
    diag.consumer_shm, diag.consumer_l1 = probe_cache(kong.db.consumers:cache_key(consumer_id))
    if diag.consumer_l1 == "negative" and diag.consumer_shm == "present" then
      diag.reason = "consumer_stale_in_worker"
      return diag
    end
    if diag.consumer_l1 == "negative" or (diag.consumer_shm == "negative" and diag.consumer_l1 ~= "present") then
      diag.reason = "consumer_not_found"
      return diag
    end
  end

  -- Only rejected by Kong when the route's jwt plugin lists these claims in
  -- claims_to_verify (Kong checks them before loading the consumer). Most
  -- routes don't, so they are checked last to keep consumer drift visible.
  local now = ngx.time()
  if type(claims.exp) == "number" and claims.exp <= now then
    diag.reason = "expired"
    return diag
  end
  if type(claims.nbf) == "number" and claims.nbf > now then
    diag.reason = "not_yet_valid"
    return diag
  end

  diag.reason = "passes_local_checks"
  return diag
end

local function record_rejection(diag, sources)
  local worker = ngx.worker.id() or -1
  local kong_side = KONG_SIDE_REJECTIONS[diag.reason] == true

  kong.log.set_serialize_value("jwt_auth.result", "rejected")
  kong.log.set_serialize_value("jwt_auth.reason", diag.reason)
  kong.log.set_serialize_value("jwt_auth.kong_side", kong_side)
  kong.log.set_serialize_value("jwt_auth.worker", worker)
  kong.log.set_serialize_value("jwt_auth.sources", sources)
  for _, field in ipairs({ "iss", "shm", "l1", "consumer_shm", "consumer_l1" }) do
    if diag[field] then
      kong.log.set_serialize_value("jwt_auth." .. field, diag[field])
    end
  end

  if not kong_side then
    return
  end

  local now = ngx.now()
  if now - last_warn_at < WARN_INTERVAL then
    suppressed_warnings = suppressed_warnings + 1
    return
  end

  kong.log.warn("jwt plugin rejected a decodable token: reason=", diag.reason,
                " iss=", diag.iss or "-", " shm=", diag.shm or "-",
                " l1=", diag.l1 or "-", " consumer_shm=", diag.consumer_shm or "-",
                " consumer_l1=", diag.consumer_l1 or "-", " sources=", sources,
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
    local ok, diag_err = pcall(function()
      local sources, token_count = collect_tokens(ngx.req, conf)
      record_rejection(diagnose_rejection(not err and jwt or nil, token_count), sources)
    end)
    if not ok then
      kong.log.err("jwt rejection diagnostics failed: ", diag_err)
    end
    return
  end

  -- "authenticated" means an auth plugin on this route accepted a credential
  -- before this plugin ran. keycloak-short-session-validator (priority 969)
  -- can still downgrade the request to anonymous afterwards.
  if kong.client.get_credential() then
    kong.log.set_serialize_value("jwt_auth.result", "authenticated")
    kong.log.set_serialize_value("jwt_auth.worker", ngx.worker.id() or -1)
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
