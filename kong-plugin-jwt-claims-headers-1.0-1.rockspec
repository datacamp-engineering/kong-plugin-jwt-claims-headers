package = "kong-plugin-jwt-claims-headers"
version = "1.0-1"
source = {
  url = "TBD"
}
description = {
  summary = "A Kong plugin that will expose JWT claims as request headers",
  license = "MIT"
}
dependencies = {
  "lua ~> 5.1"
}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.jwt-claims-headers.handler"] = "src/handler.lua",
    ["kong.plugins.jwt-claims-headers.schema"]  = "src/schema.lua"
  }
}
