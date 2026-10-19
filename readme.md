
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

## Rejection diagnostics

When a request carries a token but Kong's bundled `jwt` plugin fell back to the
anonymous consumer (`X-Anonymous-Consumer: true`), this plugin replays the jwt
plugin's checks and records the outcome in the serialized access log, which log
plugins such as `tcp-log` ship as-is. It never changes the request.

field|description
---|---
`jwt_auth.result`|`authenticated` (an auth plugin accepted a credential) or `rejected`. Only set when a token is present.
`jwt_auth.worker`|nginx worker id that handled the request.
`jwt_auth.reason`|Rejections only. `multiple_tokens`, `malformed`, `missing_iss`, `credential_not_found`, `credential_stale_in_worker`, `algorithm_mismatch`, `signature_invalid`, `consumer_stale_in_worker`, `consumer_not_found`, `expired`, `not_yet_valid` or `passes_local_checks`.
`jwt_auth.kong_side`|Rejections only. `true` when the reason points at Kong rather than the token: a stale per-worker cache entry, a missing consumer, or a token that passes every replicated check.
`jwt_auth.iss`|Token issuer, truncated to 128 characters.
`jwt_auth.shm`, `jwt_auth.l1`|What the node-wide cache and this worker's own cache hold for the issuer's credential: `present`, `negative` (cached "not found"), `absent` or `error`.
`jwt_auth.consumer_shm`, `jwt_auth.consumer_l1`|The same for the credential's consumer.
`jwt_auth.sources`|Where tokens were found: `uri`, `cookie`, `header`.

Kong-side rejections are also logged as a warning, at most once per minute per
worker. Token contents are never logged.

# Testing

To run the integration tests kong requires you to spin up a kong instance and attach it to a postgres DB. All the steps required to start the integration tests are in the `docker-compose-test.yaml`. It's required to have `docker` and `docker-compose` installed to be able to run these tests.

To get started run

```sh
make start
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

