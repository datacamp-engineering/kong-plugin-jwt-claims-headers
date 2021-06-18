#!/usr/bin/env bash
set -Eeo pipefail

# usage: file_env VAR [DEFAULT]
#    ie: file_env 'XYZ_DB_PASSWORD' 'example'
# (will allow for "$XYZ_DB_PASSWORD_FILE" to fill in the value of
#  "$XYZ_DB_PASSWORD" from a file, especially for Docker's secrets feature)
file_env() {
    local var="$1"
    local fileVar="${var}_FILE"
    local def="${2:-}"
    # Do not continue if _FILE env is not set
    if ! [ "${!fileVar:-}" ]; then
        return
    elif [ "${!var:-}" ] && [ "${!fileVar:-}" ]; then
        echo >&2 "error: both $var and $fileVar are set (but are exclusive)"
        exit 1
    fi
    local val="$def"
    if [ "${!var:-}" ]; then
        val="${!var}"
    elif [ "${!fileVar:-}" ]; then
        val="$(< "${!fileVar}")"
    fi
    export "$var"="$val"
    unset "$fileVar"
}

if [ ! -z "$(ls -A /plugin/)" ]; then
  pushd /plugin/
  /usr/local/bin/luarocks make
  popd
fi

if [[ "$1" == "kong" ]]; then
  PREFIX=${KONG_PREFIX:=/usr/local/kong}
  file_env KONG_PG_PASSWORD
  file_env KONG_PG_USER
  file_env KONG_PG_DATABASE

    if [[ "$2" == "test" ]]; then
        bin/busted $KONG_TESTS
    elif [[ "$2" == "docker-start" ]]; then
        export KONG_NGINX_DAEMON=off
        kong prepare -p "$PREFIX" "$@"

        echo $PREFIX

        echo "starting up"

        ln -sf /dev/stdout $PREFIX/logs/access.log
        ln -sf /dev/stdout $PREFIX/logs/admin_access.log
        ln -sf /dev/stderr $PREFIX/logs/error.log

        exec /usr/local/openresty/nginx/sbin/nginx \
            -p "$PREFIX" \
            -c nginx.conf
    else
        exec "$@"
    fi
else
    exec "$@"
fi
