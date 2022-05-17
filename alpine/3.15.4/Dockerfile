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
        gcc \
        libc-dev \
        libevent-dev \
        make \
        openssl-dev \
        pkgconfig \
 && apk add \
      --no-cache \
        curl \
        c-ares \
        libevent \
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
 && mkdir -p /etc/pgbouncer /var/log/pgbouncer /var/run/pgbouncer \
 && cp etc/pgbouncer.ini /etc/pgbouncer/pgbouncer.ini.example \
 && cp etc/userlist.txt /etc/pgbouncer/userlist.txt.example \
 && touch /etc/pgbouncer/userlist.txt \
 # User create \
 && addgroup -g 70 -S postgres \
 && adduser -u 70 -S -D -H -h /var/lib/postgresql -g "Postgres user" -s /bin/sh -G postgres postgres \
 && chown -R postgres /var/run/pgbouncer /etc/pgbouncer \
 # Clean
 && cd /tmp \
 && rm -rf /tmp/pgbouncer* \
 && apk del .build-deps

COPY entrypoint.sh /entrypoint.sh

USER postgres
EXPOSE 5432
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/bin/pgbouncer", "/etc/pgbouncer/pgbouncer.ini"]
