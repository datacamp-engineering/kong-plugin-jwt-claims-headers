FROM kong:2.1.4

ENV KONG_VERSION=2.1.4

# Switching to root to make development easier
USER root

RUN apk add --no-cache \
        libgcc openssl pcre tzdata libcap zip m4 \
        bash build-base gd bsd-compat-headers git libgcc libxslt \
        linux-headers make openssl openssl-dev perl libmaxminddb-dev \
        unzip zlib libressl-dev yaml-dev gettext \
    && mkdir /kong \
    && kong version \
    && git -c advice.detachedHead=false clone --branch ${KONG_VERSION} https://github.com/Kong/kong.git /kong \
    && cd /kong && make dependencies \
    && mkdir /plugin

ENV PATH="${PATH}:/usr/local/openresty/bin/"
ENV KONG_TESTS="spec/"

WORKDIR /kong

ADD docker-entrypoint.sh /

RUN chmod 770 /docker-entrypoint.sh

ENTRYPOINT [ "/docker-entrypoint.sh" ]
