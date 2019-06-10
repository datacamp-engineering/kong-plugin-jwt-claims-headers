local BasePlugin = require "kong.plugins.base_plugin"
local responses = require "kong.tools.responses"
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local req_set_header = ngx.req.set_header
local ngx_re_gmatch = ngx.re.gmatch

local JwtClaimsHeadersHandler = BasePlugin:extend()

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

function JwtClaimsHeadersHandler:new()
  JwtClaimsHeadersHandler.super.new(self, "jwt-claims-headers")
end

function JwtClaimsHeadersHandler:access(conf)
  JwtClaimsHeadersHandler.super.access(self)
  local continue_on_error = conf.continue_on_error

  local token, err = retrieve_token(ngx.req, conf)
  
  local ttype = type(token)
  if ttype ~= "string" then
    if ttype == "nil" and continue_on_error then
      return 
    end
  end

  if err and not continue_on_error then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
  end

  if not token and not continue_on_error then
    return responses.send_HTTP_UNAUTHORIZED()
  end

  local jwt, err = jwt_decoder:new(token)
  if err and not continue_on_error then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR()
  end

  ngx.ctx.jwt_logged_in = true
  ngx.ctx.jwt_claims = {}

  local claims = jwt.claims
  for claim_key,claim_value in pairs(claims) do
    for _,claim_pattern in pairs(conf.claims_to_include) do      
      if string.match(claim_key, "^"..claim_pattern.."$") then
        ngx.ctx.jwt_claims[claim_key] = claim_value
        req_set_header("X-"..claim_key, claim_value)
      end
    end
  end
end

function JwtClaimsHeadersHandler:header_filter(conf)
  JwtClaimsHeadersHandler.super.header_filter(self)

  if ngx.ctx.jwt_logged_in then
    kong.response.add_header('Set-Cookie', 'unsafe_logged_in=1; Max-Age=300; Secure;')
  end

  if ngx.ctx.jwt_claims and ngx.ctx.jwt_claims['user_id'] ~= nil then
    kong.response.add_header('Set-Cookie', string.format('unsafe_user_id=%s; Max-Age=300; Secure;', ngx.ctx.jwt_claims['user_id']))
  end
end

return JwtClaimsHeadersHandler
