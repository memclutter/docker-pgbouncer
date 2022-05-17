#!/bin/sh
# Based on https://raw.githubusercontent.com/brainsam/pgbouncer/master/entrypoint.sh

set -e

# Here are some parameters. See all on
# https://pgbouncer.github.io/config.html

config_dir=/etc/pgbouncer

if [ -n "$PGBOUNCER_INI_DATABASE_DSN" ]; then
  # Thanks to https://stackoverflow.com/a/17287984/146289

  # Allow to pass values like dj-database-url / django-environ accept
  proto="$(echo $PGBOUNCER_INI_DATABASE_DSN | grep :// | sed -e's,^\(.*://\).*,\1,g')"
  url="$(echo $PGBOUNCER_INI_DATABASE_DSN | sed -e s,$proto,,g)"

  # extract the user and password (if any)
  userpass=$(echo $url | grep @ | sed -r 's/^(.*)@([^@]*)$/\1/')
  PGBOUNCER_INI_DATABASE_PASSWORD="$(echo $userpass | grep : | cut -d: -f2)"
  if [ -n "$PGBOUNCER_INI_DATABASE_PASSWORD" ]; then
    PGBOUNCER_INI_DATABASE_USER=$(echo $userpass | grep : | cut -d: -f1)
  else
    PGBOUNCER_INI_DATABASE_USER=$userpass
  fi

  # extract the host -- updated
  hostport=`echo $url | sed -e s,$userpass@,,g | cut -d/ -f1`
  port=`echo $hostport | grep : | cut -d: -f2`
  if [ -n "$port" ]; then
      PGBOUNCER_INI_DATABASE_HOST=`echo $hostport | grep : | cut -d: -f1`
      PGBOUNCER_INI_DATABASE_PORT=$port
  else
      PGBOUNCER_INI_DATABASE_HOST=$hostport
  fi

  PGBOUNCER_INI_DATABASE_NAME="$(echo $url | grep / | cut -d/ -f2-)"
fi

# Write the password with MD5 encryption, to avoid printing it during startup.
# Notice that `docker inspect` will show unencrypted env variables.
_auth_file="${PGBOUNCER_INI_AUTH_FILE:-$config_dir/userlist.txt}"

# Workaround userlist.txt missing issue
# https://github.com/edoburu/docker-pgbouncer/issues/33
if [ ! -e "${_auth_file}" ]; then
  touch "${_auth_file}"
fi

if [ -n "$PGBOUNCER_INI_DATABASE_USER" -a -n "$PGBOUNCER_INI_DATABASE_PASSWORD" -a -e "${_auth_file}" ] && ! grep -q "^\"$PGBOUNCER_INI_DATABASE_USER\"" "${_auth_file}"; then
  if [ "$PGBOUNCER_INI_AUTH_TYPE" != "plain" ]; then
     pass="md5$(echo -n "$PGBOUNCER_INI_DATABASE_PASSWORD$PGBOUNCER_INI_DATABASE_USER" | md5sum | cut -f 1 -d ' ')"
  else
     pass="$PGBOUNCER_INI_DATABASE_PASSWORD"
  fi
  echo "\"$PGBOUNCER_INI_DATABASE_USER\" \"$pass\"" >> ${config_dir}/userlist.txt
  echo "Wrote authentication credentials to ${config_dir}/userlist.txt"
fi

if [ ! -f ${config_dir}/pgbouncer.ini ]; then
  echo "Create pgbouncer config in ${config_dir}"

# Config file is in “ini” format. Section names are between “[” and “]”.
# Lines starting with “;” or “#” are taken as comments and ignored.
# The characters “;” and “#” are not recognized when they appear later in the line.
  printf "\
;;
;; Auto generated from docker entrypoint.sh
;;
;; database name = connect string
;;
;; connect string params:
;;   dbname= host= port= user= password=
;;   client_encoding= datestyle= timezone=
;;   pool_size= connect_query=
;;   auth_user=
[databases]
${PGBOUNCER_INI_DATABASE_NAME:-*} = host=${PGBOUNCER_INI_DATABASE_HOST:?"Setup pgbouncer config error! You must set PGBOUNCER_INI_DATABASE_HOST env"} \
port=${PGBOUNCER_INI_DATABASE_PORT:-5432} user=${PGBOUNCER_INI_DATABASE_USER:-postgres}
${PGBOUNCER_INI_DATABASE_CLIENT_ENCODING:+PGBOUNCER_INI_DATABASE_CLIENT_ENCODING = ${PGBOUNCER_INI_DATABASE_CLIENT_ENCODING}\n}\

; foodb over Unix socket
;foodb =

; redirect bardb to bazdb on localhost
;bardb = host=localhost dbname=bazdb

; access to dest database will go with single user
;forcedb = host=127.0.0.1 port=300 user=baz password=foo client_encoding=UNICODE datestyle=ISO connect_query='SELECT 1'

; use custom pool sizes
;nondefaultdb = pool_size=50 reserve_pool=10

; use auth_user with auth_query if user not present in  auth_file
; auth_user must exist in auth_file
; foodb = auth_user=bar

; fallback connect string
;* = host=testserver

;; Configuration section
[pgbouncer]

;;;
;;; Administrative settings
;;;

;logfile = /var/log/pgbouncer/pgbouncer.log
;pidfile = /var/run/pgbouncer/pgbouncer.pid

;;;
;;; Where to wait for clients
;;;

; IP address or * which means all IPs
listen_addr = ${PGBOUNCER_INI_LISTEN_ADDR:-0.0.0.0}
listen_port = ${PGBOUNCER_INI_LISTEN_PORT:-5432}

; Unix socket is also used for -R.
; On Debian it should be /var/run/postgresql
unix_socket_dir =
;unix_socket_mode = 0777
;unix_socket_group =
user = postgres

;;;
;;; TLS settings for accepting clients
;;;

;; disable, allow, require, verify-ca, verify-full
;client_tls_sslmode = disable
${PGBOUNCER_INI_CLIENT_TLS_SSLMODE:+client_tls_sslmode = ${PGBOUNCER_INI_CLIENT_TLS_SSLMODE}\n}\

;; Path to file that contains trusted CA certs
;client_tls_ca_file = <system default>
${PGBOUNCER_INI_CLIENT_TLS_CA_FILE:+client_tls_ca_file = ${PGBOUNCER_INI_CLIENT_TLS_CA_FILE}\n}\

;; Private key and cert to present to clients.
;; Required for accepting TLS connections from clients.
;client_tls_key_file =
;client_tls_cert_file =
${PGBOUNCER_INI_CLIENT_TLS_KEY_FILE:+client_tls_key_file = ${PGBOUNCER_INI_CLIENT_TLS_KEY_FILE}\n}\
${PGBOUNCER_INI_CLIENT_TLS_CERT_FILE:+client_tls_cert_file = ${PGBOUNCER_INI_CLIENT_TLS_CERT_FILE}\n}\

;; fast, normal, secure, legacy, <ciphersuite string>
;client_tls_ciphers = fast
${PGBOUNCER_INI_CLIENT_TLS_CIPHERS:+client_tls_ciphers = ${PGBOUNCER_INI_CLIENT_TLS_CIPHERS}\n}\

;; all, secure, tlsv1.0, tlsv1.1, tlsv1.2
;client_tls_protocols = all
${PGBOUNCER_INI_CLIENT_TLS_PROTOCOLS:+client_tls_protocols = ${PGBOUNCER_INI_CLIENT_TLS_PROTOCOLS}\n}\

;; none, auto, legacy
;client_tls_dheparams = auto
${PGBOUNCER_INI_CLIENT_TLS_DHEPARAMS:+client_tls_dheparams = ${PGBOUNCER_INI_CLIENT_TLS_DHEPARAMS}\n}\

;; none, auto, <curve name>
;client_tls_ecdhcurve = auto
${PGBOUNCER_INI_CLIENT_TLS_ECDHCURVE:+client_tls_ecdhcurve = ${PGBOUNCER_INI_CLIENT_TLS_ECDHCURVE}\n}\

;;;
;;; TLS settings for connecting to backend databases
;;;

;; disable, allow, require, verify-ca, verify-full
;server_tls_sslmode = disable
${PGBOUNCER_INI_SERVER_TLS_SSLMODE:+server_tls_sslmode = ${PGBOUNCER_INI_SERVER_TLS_SSLMODE}\n}\

;; Path to that contains trusted CA certs
;server_tls_ca_file = <system default>
${PGBOUNCER_INI_SERVER_TLS_CA_FILE:+server_tls_ca_file = ${PGBOUNCER_INI_SERVER_TLS_CA_FILE}\n}\

;; Private key and cert to present to backend.
;; Needed only if backend server require client cert.
;server_tls_key_file =
;server_tls_cert_file =
${PGBOUNCER_INI_SERVER_TLS_KEY_FILE:+server_tls_key_file = ${PGBOUNCER_INI_SERVER_TLS_KEY_FILE}\n}\
${PGBOUNCER_INI_SERVER_TLS_CERT_FILE:+server_tls_cert_file = ${PGBOUNCER_INI_SERVER_TLS_CERT_FILE}\n}\

;; all, secure, tlsv1.0, tlsv1.1, tlsv1.2
;server_tls_protocols = all
${PGBOUNCER_INI_SERVER_TLS_PROTOCOLS:+server_tls_protocols = ${PGBOUNCER_INI_SERVER_TLS_PROTOCOLS}\n}\

;; fast, normal, secure, legacy, <ciphersuite string>
;server_tls_ciphers = fast
${PGBOUNCER_INI_SERVER_TLS_CIPHERS:+server_tls_ciphers = ${PGBOUNCER_INI_SERVER_TLS_CIPHERS}\n}\

;;;
;;; Authentication settings
;;;

; any, trust, plain, crypt, md5, cert, hba, pam
auth_type = ${PGBOUNCER_INI_AUTH_TYPE:-md5}
;auth_file = /8.0/main/global/pg_auth
;auth_file = /etc/pgbouncerPAM/userlist.txt
auth_file = ${PGBOUNCER_INI_AUTH_FILE:-$config_dir/userlist.txt}

;; Path to HBA-style auth config
${PGBOUNCER_INI_AUTH_HBA_FILE:+auth_hba_file = ${PGBOUNCER_INI_AUTH_HBA_FILE}\n}\

;; Query to use to fetch password from database.  Result
;; must have 2 columns - username and password hash.
${PGBOUNCER_INI_AUTH_USER:+auth_user = ${PGBOUNCER_INI_AUTH_USER}\n}\
;auth_query = SELECT usename, passwd FROM pg_shadow WHERE usename=$1
;auth_query = SELECT usename, passwd FROM gp_user_search($1)
${PGBOUNCER_INI_AUTH_QUERY:+auth_query = ${PGBOUNCER_INI_AUTH_QUERY}\n}\

;;;
;;; Users allowed into database 'pgbouncer'
;;;

; comma-separated list of users, who are allowed to change settings
;admin_users = user2, someadmin, otheradmin
admin_users = ${PGBOUNCER_INI_ADMIN_USERS:-postgres}

; comma-separated list of users who are just allowed to use SHOW command
${PGBOUNCER_INI_STATS_USERS:+stats_users = ${PGBOUNCER_INI_STATS_USERS}\n}\

;;;
;;; Pooler personality questions
;;;

; When server connection is released back to pool:
;   session      - after client disconnects
;   transaction  - after transaction finishes
;   statement    - after statement finishes
;pool_mode = session
${PGBOUNCER_INI_POOL_MODE:+pool_mode = ${PGBOUNCER_INI_POOL_MODE}\n}\

;
; Query for cleaning connection immediately after releasing from client.
; No need to put ROLLBACK here, pgbouncer does not reuse connections
; where transaction is left open.
;
; Query for 8.3+:
;   DISCARD ALL;
;
; Older versions:
;   RESET ALL; SET SESSION AUTHORIZATION DEFAULT
;
; Empty if transaction pooling is in use.
;
;server_reset_query = DISCARD ALL
${PGBOUNCER_INI_SERVER_RESET_QUERY:+server_reset_query = ${PGBOUNCER_INI_SERVER_RESET_QUERY}\n}\


; Whether server_reset_query should run in all pooling modes.
; If it is off, server_reset_query is used only for session-pooling.
;server_reset_query_always = 0
${PGBOUNCER_INI_SERVER_RESET_QUERY_ALWAYS:+server_reset_query_always = ${PGBOUNCER_INI_SERVER_RESET_QUERY_ALWAYS}\n}\

;
; Comma-separated list of parameters to ignore when given
; in startup packet.  Newer JDBC versions require the
; extra_float_digits here.
;
ignore_startup_parameters = ${PGBOUNCER_INI_IGNORE_STARTUP_PARAMETERS:-extra_float_digits}

;
; When taking idle server into use, this query is ran first.
;   SELECT 1
;
;server_check_query = select 1
${PGBOUNCER_INI_SERVER_CHECK_QUERY:+server_check_query = ${PGBOUNCER_INI_SERVER_CHECK_QUERY}\n}\

; If server was used more recently that this many seconds ago,
; skip the check query.  Value 0 may or may not run in immediately.
;server_check_delay = 30
${PGBOUNCER_INI_SERVER_CHECK_DELAY:+server_check_delay = ${PGBOUNCER_INI_SERVER_CHECK_DELAY}\n}\

; Close servers in session pooling mode after a RECONNECT, RELOAD,
; etc. when they are idle instead of at the end of the session.
;server_fast_close = 0
${PGBOUNCER_INI_SERVER_FAST_CLOSE:+server_fast_close = ${PGBOUNCER_INI_SERVER_FAST_CLOSE}\n}\

;; Use <appname - host> as application_name on server.
;application_name_add_host = 0
${PGBOUNCER_INI_APPLICATION_NAME_ADD_HOST:+application_name_add_host = ${PGBOUNCER_INI_APPLICATION_NAME_ADD_HOST}\n}\

;;;
;;; Connection limits
;;;

; total number of clients that can connect
${PGBOUNCER_INI_MAX_CLIENT_CONN:+max_client_conn = ${PGBOUNCER_INI_MAX_CLIENT_CONN}\n}\

; default pool size.  20 is good number when transaction pooling
; is in use, in session pooling it needs to be the number of
; max clients you want to handle at any moment
${PGBOUNCER_INI_DEFAULT_POOL_SIZE:+default_pool_size = ${PGBOUNCER_INI_DEFAULT_POOL_SIZE}\n}\

;; Minimum number of server connections to keep in pool.
;min_pool_size = 50
${PGBOUNCER_INI_MIN_POOL_SIZE:+min_pool_size = ${PGBOUNCER_INI_MIN_POOL_SIZE}\n}\

; how many additional connection to allow in case of trouble
${PGBOUNCER_INI_RESERVE_POOL_SIZE:+reserve_pool_size = ${PGBOUNCER_INI_RESERVE_POOL_SIZE}\n}\

; if a clients needs to wait more than this many seconds, use reserve pool
${PGBOUNCER_INI_RESERVE_POOL_TIMEOUT:+reserve_pool_timeout = ${PGBOUNCER_INI_RESERVE_POOL_TIMEOUT}\n}\

; how many total connections to a single database to allow from all pools
${PGBOUNCER_INI_MAX_DB_CONNECTIONS:+max_db_connections = ${PGBOUNCER_INI_MAX_DB_CONNECTIONS}\n}\
${PGBOUNCER_INI_MAX_USER_CONNECTIONS:+max_user_connections = ${PGBOUNCER_INI_MAX_USER_CONNECTIONS}\n}\

; If off, then server connections are reused in LIFO manner
;server_round_robin = 0
${PGBOUNCER_INI_SERVER_ROUND_ROBIN:+server_round_robin = ${PGBOUNCER_INI_SERVER_ROUND_ROBIN}\n}\

;;;
;;; Logging
;;;

;; Syslog settings
syslog = 0
syslog_facility = daemon,auth
;syslog_ident = pgbouncer

; log if client connects or server connection is made
${PGBOUNCER_INI_LOG_CONNECTIONS:+log_connections = ${PGBOUNCER_INI_LOG_CONNECTIONS}\n}\

; log if and why connection was closed
${PGBOUNCER_INI_LOG_DISCONNECTIONS:+log_disconnections = ${PGBOUNCER_INI_LOG_DISCONNECTIONS}\n}\

; log error messages pooler sends to clients
${PGBOUNCER_INI_LOG_POOLER_ERRORS:+log_pooler_errors = ${PGBOUNCER_INI_LOG_POOLER_ERRORS}\n}\

${PGBOUNCER_INI_LOG_STATS:+log_stats = ${PGBOUNCER_INI_LOG_STATS}\n}\

;; Period for writing aggregated stats into log.
;stats_period = 60
${PGBOUNCER_INI_STATS_PERIOD:+stats_period = ${PGBOUNCER_INI_STATS_PERIOD}\n}\

;; Logging verbosity.  Same as -v switch on command line.
${PGBOUNCER_INI_VERBOSE:+verbose = ${PGBOUNCER_INI_VERBOSE}\n}\


;;;
;;; Timeouts
;;;

;; Close server connection if its been connected longer.
;server_lifetime = 3600
${PGBOUNCER_INI_SERVER_LIFETIME:+server_lifetime = ${PGBOUNCER_INI_SERVER_LIFETIME}\n}\

;; Close server connection if its not been used in this time.
;; Allows to clean unnecessary connections from pool after peak.
;server_idle_timeout = 600
${PGBOUNCER_INI_SERVER_IDLE_TIMEOUT:+server_idle_timeout = ${PGBOUNCER_INI_SERVER_IDLE_TIMEOUT}\n}\

;; Cancel connection attempt if server does not answer takes longer.
${PGBOUNCER_INI_SERVER_CONNECT_TIMEOUT:+server_connect_timeout = ${PGBOUNCER_INI_SERVER_CONNECT_TIMEOUT}\n}\

;; If server login failed (server_connect_timeout or auth failure)
;; then wait this many second.
${PGBOUNCER_INI_SERVER_LOGIN_RETRY:+server_login_retry = ${PGBOUNCER_INI_SERVER_LOGIN_RETRY}\n}\

;; Dangerous.  Server connection is closed if query does not return
;; in this time.  Should be used to survive network problems,
;; _not_ as statement_timeout. (default: 0)
;query_timeout = 0
${PGBOUNCER_INI_QUERY_TIMEOUT:+query_timeout = ${PGBOUNCER_INI_QUERY_TIMEOUT}\n}\

;; Dangerous.  Client connection is closed if the query is not assigned
;; to a server in this time.  Should be used to limit the number of queued
;; queries in case of a database or network failure. (default: 120)
${PGBOUNCER_INI_QUERY_WAIT_TIMEOUT:+query_wait_timeout = ${PGBOUNCER_INI_QUERY_WAIT_TIMEOUT}\n}\

;; Dangerous.  Client connection is closed if no activity in this time.
;; Should be used to survive network problems. (default: 0)
;client_idle_timeout = 0
${PGBOUNCER_INI_CLIENT_IDLE_TIMEOUT:+client_idle_timeout = ${PGBOUNCER_INI_CLIENT_IDLE_TIMEOUT}\n}\

;; Disconnect clients who have not managed to log in after connecting
;; in this many seconds.
${PGBOUNCER_INI_CLIENT_LOGIN_TIMEOUT:+client_login_timeout = ${PGBOUNCER_INI_CLIENT_LOGIN_TIMEOUT}\n}\

;; Clean automatically created database entries (via "*") if they
;; stay unused in this many seconds.
; autodb_idle_timeout = 3600
${PGBOUNCER_INI_AUTODB_IDLE_TIMEOUT:+autodb_idle_timeout = ${PGBOUNCER_INI_AUTODB_IDLE_TIMEOUT}\n}\

;; How long SUSPEND/-R waits for buffer flush before closing connection.
;suspend_timeout = 10
${PGBOUNCER_INI_SUSPEND_TIMEOUT:+suspend_timeout = ${PGBOUNCER_INI_SUSPEND_TIMEOUT}\n}\

;; Close connections which are in "IDLE in transaction" state longer than
;; this many seconds.
;idle_transaction_timeout = 0
${PGBOUNCER_INI_IDLE_TRANSACTION_TIMEOUT:+idle_transaction_timeout = ${PGBOUNCER_INI_IDLE_TRANSACTION_TIMEOUT}\n}\

;;;
;;; Low-level tuning options
;;;

;; buffer for streaming packets
;pkt_buf = 4096
${PGBOUNCER_INI_PKT_BUF:+pkt_buf = ${PGBOUNCER_INI_PKT_BUF}\n}\

;; man 2 listen
;listen_backlog = 128
${PGBOUNCER_INI_LISTEN_BACKLOG:+listen_backlog = ${PGBOUNCER_INI_LISTEN_BACKLOG}\n}\

;; Max number pkt_buf to process in one event loop.
;sbuf_loopcnt = 5
${PGBOUNCER_INI_SBUF_LOOPCNT:+sbuf_loopcnt = ${PGBOUNCER_INI_SBUF_LOOPCNT}\n}\

;; Maximum PostgreSQL protocol packet size.
;max_packet_size = 2147483647
${PGBOUNCER_INI_MAX_PACKET_SIZE:+max_packet_size = ${PGBOUNCER_INI_MAX_PACKET_SIZE}\n}\

;; networking options, for info: man 7 tcp

;; Linux: notify program about new connection only if there
;; is also data received.  (Seconds to wait.)
;; On Linux the default is 45, on other OS'es 0.
;tcp_defer_accept = 0
${PGBOUNCER_INI_TCP_DEFER_ACCEPT:+tcp_defer_accept = ${PGBOUNCER_INI_TCP_DEFER_ACCEPT}\n}\

;; In-kernel buffer size (Linux default: 4096)
;tcp_socket_buffer = 0
${PGBOUNCER_INI_TCP_SOCKET_BUFFER:+tcp_socket_buffer = ${PGBOUNCER_INI_TCP_SOCKET_BUFFER}\n}\

;; whether tcp keepalive should be turned on (0/1)
;tcp_keepalive = 1
${PGBOUNCER_INI_TCP_KEEPALIVE:+tcp_keepalive = ${PGBOUNCER_INI_TCP_KEEPALIVE}\n}\

;; The following options are Linux-specific.
;; They also require tcp_keepalive=1.

;; count of keepalive packets
;tcp_keepcnt = 0
${PGBOUNCER_INI_TCP_KEEPCNT:+tcp_keepcnt = ${PGBOUNCER_INI_TCP_KEEPCNT}\n}\

;; how long the connection can be idle,
;; before sending keepalive packets
;tcp_keepidle = 0
${PGBOUNCER_INI_TCP_KEEPIDLE:+tcp_keepidle = ${PGBOUNCER_INI_TCP_KEEPIDLE}\n}\

;; The time between individual keepalive probes.
;tcp_keepintvl = 0
${PGBOUNCER_INI_TCP_KEEPINTVL:+tcp_keepintvl = ${PGBOUNCER_INI_TCP_KEEPINTVL}\n}\

;; Sets the TCP_USER_TIMEOUT socket option. This specifies the maximum amount of time in milliseconds that transmitted data may remain unacknowledged before the TCP connection is forcibly closed. If set to 0, then operating system’s default is used.
;; This is currently only supported on Linux.
;tcp_user_timeout = 0
${PGBOUNCER_INI_TCP_USER_TIMEOUT:+tcp_user_timeout = ${PGBOUNCER_INI_TCP_USER_TIMEOUT}\n}\

;; DNS lookup caching time
;dns_max_ttl = 15
${PGBOUNCER_INI_DNS_MAX_TTL:+dns_max_ttl = ${PGBOUNCER_INI_DNS_MAX_TTL}\n}\

;; DNS zone SOA lookup period
;dns_zone_check_period = 0
${PGBOUNCER_INI_DNS_ZONE_CHECK_PERIOD:+dns_zone_check_period = ${PGBOUNCER_INI_DNS_ZONE_CHECK_PERIOD}\n}\

;; DNS negative result caching time
;dns_nxdomain_ttl = 15
${PGBOUNCER_INI_DNS_NXDOMAIN_TTL:+dns_nxdomain_ttl = ${PGBOUNCER_INI_DNS_NXDOMAIN_TTL}\n}\

;;;
;;; Random stuff
;;;

;; Hackish security feature.  Helps against SQL-injection - when PQexec is disabled,
;; multi-statement cannot be made.
;disable_pqexec = 0
${PGBOUNCER_INI_DISABLE_PQEXEC:+disable_pqexec = ${PGBOUNCER_INI_DISABLE_PQEXEC}\n}\

;; Config file to use for next RELOAD/SIGHUP.
;; By default contains config file from command line.
;conffile

;; Win32 service name to register as.  job_name is alias for service_name,
;; used by some Skytools scripts.
;service_name = pgbouncer
;job_name = pgbouncer

;; Read additional config from the /etc/pgbouncer/pgbouncer-other.ini file
;%include /etc/pgbouncer/pgbouncer-other.ini
" > ${config_dir}/pgbouncer.ini
cat ${config_dir}/pgbouncer.ini
echo "Starting $*..."
fi

exec "$@"