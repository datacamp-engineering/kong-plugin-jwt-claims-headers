
# kong-plugin-jwt-claims-headers

Add unencrypted, base64-decoded claims from a JWT payload as request headers to
the upstream service.

## How it works

When enabled, this plugin will add new headers to requests based on the claims 
in the JWT provided in the request. The generated headers follow the naming 
convention of `x-<claim-name>`. For example, if the JWT payload object is

```json
{
  "sub"   : "1234567890",
  "name"  : "John Doe",
  "admin" : true
}
```

then the following headers would be added

```
x-sub   : "1234567890"
x-name  : "John Doe"
x-admin : true
```

## Configuration

Similar to the built-in JWT Kong plugin, you can associate the jwt-claims-headers
plugin with an api with the following request

```bash
curl -X POST http://localhost:8001/apis/29414666-6b91-430a-9ff0-50d691b03a45/plugins \
  --data "name=jwt-claims-headers" \
  --data "config.uri_param_names=jwt" \
  --data "config.claims_to_include=.*" \
  --data "config.continue_on_error=true"
```

form parameter|required|description
---|---|---
`name`|*required*|The name of the plugin to use, in this case: `jwt-claims-headers`
`uri_param_names`|*optional*|A list of querystring parameters that Kong will inspect to retrieve JWTs. Defaults to `jwt`.
`claims_to_include`|*required*|A list of claims that Kong will expose in request headers. Lua pattern expressions are valid, e.g., `kong-.*` will include `kong-id`, `kong-email`, etc. Defaults to `.*` (include all claims). 
`continue_on_error`|*required*|Whether to send the request to the upstream service if a failure occurs (no JWT token present, error decoding, etc). Defaults to `true`.

# Testing

To run the integration tests kong requires you to spin up a kong instance and attach it to a postgres DB. All the steps required to start the integration tests are in the `docker-compose-test.yaml`. It's required to have `docker` and `docker-compose` installed to be able to run these tests.

To get started run

```sh
make start-test
```

Ths will spin up all the required components. Run the kong migrations for the specified version and run the integration test for this plugin.

To rerun the tests simply run:

```sh
make test
```

Volumes are setup so that changes are automatically picked up so that `make test` always test for the latest changes on disk.

To do some manual testing run:

```sh
make demo
```

This wills pin up a demo environment of kong without a DB using a declarative config defined in `config/kong.yml`

