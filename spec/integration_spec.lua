local helpers = require "spec.helpers"
local cjson = require "cjson"
local jwt_encoder = require "kong.plugins.jwt.jwt_parser"

local rs256_private_key = [[
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAw5mp3MS3hVLkHwB9lMrEx34MjYCmKeH/XeMLexNpTd1FzuNv
6rArovTY763CDo1Tp0xHz0LPlDJJtpqAgsnfDwCcgn6ddZTo1u7XYzgEDfS8J4SY
dcKxZiSdVTpb9k7pByXfnwK/fwq5oeBAJXISv5ZLB1IEVZHhUvGCH0udlJ2vadqu
R03phBHcvlNmMbJGWAetkdcKyi+7TaW7OUSjlge4WYERgYzBB6eJH+UfPjmw3aSP
ZcNXt2RckPXEbNrL8TVXYdEvwLJoJv9/I8JPFLiGOm5uTMEk8S4txs2efueg1Xyy
milCKzzuXlJvrvPA4u6HI7qNvuvkvUjQmwBHgwIDAQABAoIBAQCP3ZblTT8abdRh
xQ+Y/+bqQBjlfwk4ZwRXvuYz2Rwr7CMrP3eSq4785ZAmAaxo3aP4ug9bL23UN4Sm
LU92YxqQQ0faZ1xTHnp/k96SGKJKzYYSnuEwREoMscOS60C2kmWtHzsyDmhg/bd5
i6JCqHuHtPhsYvPTKGANjJrDf+9gXazArmwYrdTnyBeFC88SeRG8uH2lP2VyqHiw
ZvEQ3PkRRY0yJRqEtrIRIlgVDuuu2PhPg+MR4iqR1RONjDUFaSJjR7UYWY/m/dmg
HlalqpKjOzW6RcMmymLKaW6wF3y8lbs0qCjCYzrD3bZnlXN1kIw6cxhplfrSNyGZ
BY/qWytJAoGBAO8UsagT8tehCu/5smHpG5jgMY96XKPxFw7VYcZwuC5aiMAbhKDO
OmHxYrXBT/8EQMIk9kd4r2JUrIx+VKO01wMAn6fF4VMrrXlEuOKDX6ZE1ay0OJ0v
gCmFtKB/EFXXDQLV24pgYgQLxnj+FKFV2dQLmv5ZsAVcmBHSkM9PBdUlAoGBANFx
QPuVaSgRLFlXw9QxLXEJbBFuljt6qgfL1YDj/ANgafO8HMepY6jUUPW5LkFye188
J9wS+EPmzSJGxdga80DUnf18yl7wme0odDI/7D8gcTfu3nYcCkQzeykZNGAwEe+0
SvhXB9fjWgs8kFIjJIxKGmlMJRMHWN1qaECEkg2HAoGBAIb93EHW4as21wIgrsPx
5w8up00n/d7jZe2ONiLhyl0B6WzvHLffOb/Ll7ygZhbLw/TbAePhFMYkoTjCq++z
UCP12i/U3yEi7FQopWvgWcV74FofeEfoZikLwa1NkV+miUYskkVTnoRCUdJHREbE
PrYnx2AOLAEbAxItHm6vY8+xAoGAL85JBePpt8KLu+zjfximhamf6C60zejGzLbD
CgN/74lfRcoHS6+nVs73l87n9vpZnLhPZNVTo7QX2J4M5LHqGj8tvMFyM895Yv+b
3ihnFVWjYh/82Tq3QS/7Cbt+EAKI5Yzim+LJoIZ9dBkj3Au3eOolMym1QK2ppAh4
uVlJORsCgYBv/zpNukkXrSxVHjeZj582nkdAGafYvT0tEQ1u3LERgifUNwhmHH+m
1OcqJKpbgQhGzidXK6lPiVFpsRXv9ICP7o96FjmQrMw2lAfC7stYnFLKzv+cj8L9
h4hhNWM6i/DHXjPsHgwdzlX4ulq8M7dR8Oqm9DrbdAyWz8h8/kzsnA==
-----END RSA PRIVATE KEY-----
]]

local rs256_public_key = [[
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw5mp3MS3hVLkHwB9lMrE
x34MjYCmKeH/XeMLexNpTd1FzuNv6rArovTY763CDo1Tp0xHz0LPlDJJtpqAgsnf
DwCcgn6ddZTo1u7XYzgEDfS8J4SYdcKxZiSdVTpb9k7pByXfnwK/fwq5oeBAJXIS
v5ZLB1IEVZHhUvGCH0udlJ2vadquR03phBHcvlNmMbJGWAetkdcKyi+7TaW7OUSj
lge4WYERgYzBB6eJH+UfPjmw3aSPZcNXt2RckPXEbNrL8TVXYdEvwLJoJv9/I8JP
FLiGOm5uTMEk8S4txs2efueg1XyymilCKzzuXlJvrvPA4u6HI7qNvuvkvUjQmwBH
gwIDAQAB
-----END PUBLIC KEY-----
]]

describe("jwt-claims-headers", function()

  local bp = helpers.get_db_utils("postgres")
  local jwt_secret

  setup(function()
    local service = bp.services:insert {
      name = "test-service",
      host = "httpbin",
      port = 80
    }

    local route = bp.routes:insert({
      name = "root",
      preserve_host = true,
      paths = { "/" },
      hosts = { "test.com" },
      protocols = { "http", "https" },
      service = { id = service.id }
    })

    local anonymous = bp.consumers:insert({
      username = "anonymous"
    })

    local users = bp.consumers:insert({
      username = "datacamp-users"
    })
    
    jwt_secret = bp.jwt_secrets:insert({
      consumer       = { id = users.id },
      algorithm      = "RS256",
      key            = "https://www.datacamp.com",
      rsa_public_key = rs256_public_key
    })

    bp.plugins:insert({
      name       = "jwt",
      service    = { id = service.id },
      config     = {
        secret_is_base64 = false,
        run_on_preflight = true,
        anonymous        = anonymous.id,
        cookie_names     = { "_dct" }
      },
    })

    bp.plugins:insert({
      name = "jwt-claims-headers",
      service = { id = service.id },
      config = {
        continue_on_error = true,
        cookie_names = { "_dct" }
      }
    })

    -- start Kong with your testing Kong configuration (defined in "spec.helpers")
    assert(helpers.start_kong( { plugins = "bundled,jwt-claims-headers" }))

    admin_client = helpers.admin_client()
  end)

  teardown(function()
    if admin_client then
      admin_client:close()
    end

    helpers.stop_kong()
  end)

  before_each(function()
    proxy_client = helpers.proxy_client()
  end)

  after_each(function()
    if proxy_client then
      proxy_client:close()
    end
  end)

  describe("claims headers", function()
    it("adds any claims from a valid jwt as headers to the proxied request", function()
      local payload = {
        iss = jwt_secret.key,
        nbf = os.time(),
        iat = os.time(),
        exp = os.time() + 3600,
        user_id = 123
      }
      local jwt = jwt_encoder.encode(payload, rs256_private_key, 'RS256')
      local res = assert(proxy_client:send {
        method  = "GET",
        path    = "/headers",
        headers = {
          ["Host"] = "test.com",
          ["Cookie"] = "_dct=" .. jwt .. ";"
        },
      })
      -- Hack the X-Powered-By header so that the kong helpers know the request is coming from mockbin
      -- (https://github.com/Kong/kong/blob/8f36f3175c6a45be237d9ccd4ba227ff66e12d99/spec/helpers.lua#L1329)
      res.headers["X-Powered-By"] = "mock_upstream"
      
      assert.response(res).has.status(200)
      local user_id = assert.request(res).has.header("x-user-id")
      assert.equal("123", user_id)
      local iss = assert.request(res).has.header("x-iss")
      assert.equal(jwt_secret.key, iss)

      assert.request(res).has.header("x-nbf")
      assert.request(res).has.header("x-iat")
      assert.request(res).has.header("x-exp")
    end)

    it("does not add any claims as headers when the jwt is invalid", function()
      local jwt = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3d3dy5kYXRhY2FtcC5jb20iLCJqdGkiOiI4NzQ4NTI5LWMzNzI0NjNjYWY4NGI0NjkzMDE3ZDI3NmViMDZmODc4N2JhYjhiYzE0OTY0NGRhNmQ5MmE4YTViYzNmOCIsInVzZXJfaWQiOjg3NDgxMTAsImV4cCI6MTYzMTM5MzU4NH0."
      local res = assert(proxy_client:send {
        method  = "GET",
        path    = "/headers",
        headers = {
          ["Host"] = "test.com",
          ["Cookie"] = "_dct=" .. jwt .. ";"
        },
      })
      -- Hack the X-Powered-By header so that the kong helpers know the request is coming from mockbin
      -- (https://github.com/Kong/kong/blob/8f36f3175c6a45be237d9ccd4ba227ff66e12d99/spec/helpers.lua#L1329)
      res.headers["X-Powered-By"] = "mock_upstream"
      
      assert.response(res).has.status(200)
      assert.request(res).has.no.header("x-user-id")
      assert.request(res).has.no.header("x-iss")
      assert.request(res).has.no.header("x-nbf")
      assert.request(res).has.no.header("x-iat")
      assert.request(res).has.no.header("x-exp")
    end)
  end)

  describe("x-user_id header", function() 
    it("removes any x-user-id header if set on the request", function()
      local res = assert(proxy_client:send {
        method  = "GET",
        path    = "/headers",
        headers = {
          ["Host"] = "test.com",
          ["X-user_id"] = "456"
        },
      })
      -- Hack the X-Powered-By header so that the kong helpers know the request is coming from mockbin
      -- (https://github.com/Kong/kong/blob/8f36f3175c6a45be237d9ccd4ba227ff66e12d99/spec/helpers.lua#L1329)
      res.headers["X-Powered-By"] = "mock_upstream"
      
      assert.response(res).has.status(200)
      assert.request(res).has.no.header("x-user-id")
    end)
  end)
end)
