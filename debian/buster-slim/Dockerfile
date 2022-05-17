FROM debian:buster-slim

# Build args
ARG PGBOUNCER_VERSION=1.17.0

# Environment vars
ENV DEBIAN_FRONTEND=noninteractive

# Metadata/labels
LABEL org.opencontainers.image.authors="memclutter@gmail.com"

# Install build tools
RUN apt-get update -qqy \
 && apt-get install  \
      -qqy \
        build-essential \
        curl \
        libc-ares-dev \
        libevent-dev \
        libssl-dev \
        pkg-config \
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
 && addgroup --gid 70 --system postgres \
 && adduser --uid 70 --system --disabled-password --no-create-home --home /var/lib/postgresql --gecos "Postgres user" --shell /bin/sh --gid 70 postgres \
 && chown -R postgres /var/run/pgbouncer /etc/pgbouncer \
 # Clean
 && cd /tmp \
 && rm -rf /tmp/pgbouncer* \
 && rm -rf /var/lib/apt/lists/*

COPY --chown=postgres:postgres entrypoint.sh /entrypoint.sh

USER postgres
EXPOSE 5432
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/local/bin/pgbouncer", "/etc/pgbouncer/pgbouncer.ini"]
