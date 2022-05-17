FROM alpine:3.15.4

# Build args
ARG PGBOUNCER_VERSION=1.17.0

# Metadata/labels
LABEL org.opencontainers.image.authors="memclutter@gmail.com"

# Install build tools
RUN apk add \
      --no-cache \
      --virtual .build-deps \
        autoconf \
        c-ares-dev \
        curl \
        gcc \
        libc-dev \
        libevent \
        libevent-dev \
        make \
        openssl-dev \
        pkgconfig \
 # Download pgbouncer distribution
 && curl \
      -o /tmp/pgbouncer-$PGBOUNCER_VERSION.tar.gz \
      -L https://pgbouncer.github.io/downloads/files/$PGBOUNCER_VERSION/pgbouncer-$PGBOUNCER_VERSION.tar.gz \
 # Extract distribution
 && cd /tmp \
 && tar xvfz /tmp/pgbouncer-$PGBOUNCER_VERSION.tar.gz \
 # Configure and build
 && cd pgbouncer-$PGBOUNCER_VERSION \
 && ./configure \
      --prefix=/usr/local \
      --with-cares \
 && make \
 && make install \
 # Clean
 && cd /tmp \
 && rm -rf /tmp/pgbouncer* \
 && apk del .build-deps

CMD ["/usr/local/bin/pgbouncer"]
