return {
  no_consumer = true,
  fields = {
    uri_param_names = {type = "array", default = {"jwt"}},
    cookie_names = {type = "array", default = {}},
    claims_to_include = {type = "array", default = {".*"}},
    continue_on_error = {type = "boolean", default = true}
  }
}
