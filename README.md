# docker-pgbouncer
The repository contains a dockerized pgbouncer.

Available base images:
- debian:buster-slim
- alpine:3.15.4

Available pgbouncer versions:
- 1.14.0
- 1.15.0
- 1.16.0
- 1.16.1
- 1.17.0

## Environment variables & configuration

There are two ways to configure dockerized pgbouncer:

1. Upload config files to container (path `/etc/pgbouncer/pgbouncer.ini` and `/etc/pgbouncer/userlist.txt`)
2. Set environment variables starting with prefix `PGBOUNCER_INI_*`
    here are some env vars:
        - `PGBOUNCER_INI_DATABASE_DSN` - data source name for database, example `postgresql://user:pass@host:port/dbname`
        - `PGBOUNCER_INI_DATABASE_HOST` - hostname
        - `PGBOUNCER_INI_DATABASE_USER` - user
        - `PGBOUNCER_INI_DATABASE_PASSWORD` - password
        - `PGBOUNCER_INI_DATABASE_NAME` - database name
        - `PGBOUNCER_INI_POOL_MODE` - set pool mode
        - etc
