#!/usr/bin/env bash
set -Eeuo pipefail

vault_pid=
tunnel_pid=
secret_dir=
supervisor_dir=/tmp/agent-vault-supervisor
supervisor_dir_created=false

cleanup_children() {
    for pid in "$vault_pid" "$tunnel_pid"; do
        [[ -n "$pid" ]] || continue
        kill -TERM "$pid" 2>/dev/null || true
    done
    for pid in "$vault_pid" "$tunnel_pid"; do
        [[ -n "$pid" ]] || continue
        wait "$pid" 2>/dev/null || true
    done
    [[ -z "$secret_dir" ]] || rm -rf "$secret_dir"
    if [[ "$supervisor_dir_created" == true ]]; then
        rm -f "$supervisor_dir/processes"
        rmdir "$supervisor_dir" 2>/dev/null || true
    fi
}

fatal() {
    printf 'agent-vault startup failed: %s\n' "$1" >&2
    cleanup_children
    exit 1
}
trap cleanup_children EXIT

[[ $# -gt 0 && "$1" == server ]] || fatal 'this image only runs the server command'
: "${AGENT_VAULT_MASTER_PASSWORD:?AGENT_VAULT_MASTER_PASSWORD is required}"

case "${ARCADE_VAULT_MTLS_ENABLED:-}" in
    true | false) ;;
    *) fatal 'ARCADE_VAULT_MTLS_ENABLED must be true or false' ;;
esac

allow_private_ranges=${AGENT_VAULT_ALLOW_PRIVATE_RANGES:-false}
case "${allow_private_ranges,,}" in
    true | 1 | t) fatal 'private upstream ranges must remain blocked' ;;
esac
[[ -z "${AGENT_VAULT_NETWORK_ALLOWLIST:-}" ]] || fatal 'network allowlists are not enabled for this broker'
dev_mode=${AGENT_VAULT_DEV_MODE:-false}
case "${dev_mode,,}" in
    true | 1 | t) fatal 'development mode must remain disabled' ;;
esac
[[ -z "${DATABASE_URL:-}" ]] || fatal 'DATABASE_URL must be unset; this deployment uses persistent SQLite'
[[ -z "${INFISICAL_URL:-}" ]] || fatal 'Infisical integration is not enabled for this standalone OSS broker'

umask 077
secret_dir=$(mktemp -d /tmp/agent-vault-transport.XXXXXX)
chmod 700 "$secret_dir"

if [[ "$ARCADE_VAULT_MTLS_ENABLED" == true ]]; then
    : "${ARCADE_VAULT_MTLS_SERVER_CERT_B64:?server certificate is required when mTLS is enabled}"
    : "${ARCADE_VAULT_MTLS_SERVER_KEY_B64:?server private key is required when mTLS is enabled}"
    : "${ARCADE_VAULT_MTLS_CLIENT_TRUST_BUNDLE_B64:?client trust bundle is required when mTLS is enabled}"

    printf '%s' "$ARCADE_VAULT_MTLS_SERVER_CERT_B64" | base64 -d >"$secret_dir/server.crt.pem" \
        || fatal 'server certificate is not valid base64'
    printf '%s' "$ARCADE_VAULT_MTLS_SERVER_KEY_B64" | base64 -d >"$secret_dir/server.key.pem" \
        || fatal 'server private key is not valid base64'
    printf '%s' "$ARCADE_VAULT_MTLS_CLIENT_TRUST_BUNDLE_B64" | base64 -d >"$secret_dir/client-trust.pem" \
        || fatal 'client trust bundle is not valid base64'
    chmod 600 "$secret_dir"/*

    # Railway variables are only the input channel. Keep the key material out
    # of both child process environments and all logs after writing mode-0600
    # files to ephemeral container storage.
    unset ARCADE_VAULT_MTLS_SERVER_CERT_B64
    unset ARCADE_VAULT_MTLS_SERVER_KEY_B64
    unset ARCADE_VAULT_MTLS_CLIENT_TRUST_BUNDLE_B64

    cat >"$secret_dir/stunnel.conf" <<EOF
foreground = yes
debug = warning

[agent-vault-proxy]
accept = 0.0.0.0:14443
connect = 127.0.0.1:14322
cert = $secret_dir/server.crt.pem
key = $secret_dir/server.key.pem
CAfile = $secret_dir/client-trust.pem
verifyChain = yes
verifyPeer = yes
requireCert = yes
sslVersionMin = TLSv1.2
EOF
    chmod 600 "$secret_dir/stunnel.conf"
fi

master_password=$AGENT_VAULT_MASTER_PASSWORD
unset AGENT_VAULT_MASTER_PASSWORD

mkdir -m 700 "$supervisor_dir" 2>/dev/null \
    || fatal 'supervisor state directory already exists'
supervisor_dir_created=true
AGENT_VAULT_MASTER_PASSWORD="$master_password" /usr/local/bin/agent-vault "$@" &
vault_pid=$!
trap 'trap - TERM INT; cleanup_children; exit 0' TERM INT

if [[ "$ARCADE_VAULT_MTLS_ENABLED" == true ]]; then
    # The Vault server treats failure to bind the MITM listener as non-fatal.
    # Do not open the mTLS ingress until both private listeners are live.
    ready=false
    for _ in {1..60}; do
        kill -0 "$vault_pid" 2>/dev/null || fatal 'Agent Vault exited before becoming ready'
        if wget -q -O /dev/null http://127.0.0.1:14321/health \
            && (exec 3<>/dev/tcp/127.0.0.1/14322) 2>/dev/null; then
            ready=true
            break
        fi
        sleep 1
    done
    [[ "$ready" == true ]] || fatal 'Agent Vault control or proxy listener did not become ready'

    /usr/bin/stunnel "$secret_dir/stunnel.conf" &
    tunnel_pid=$!
    tunnel_ready=false
    for _ in {1..60}; do
        kill -0 "$tunnel_pid" 2>/dev/null || fatal 'stunnel exited before becoming ready'
        if (exec 4<>/dev/tcp/127.0.0.1/14443) 2>/dev/null; then
            tunnel_ready=true
            break
        fi
        sleep 1
    done
    [[ "$tunnel_ready" == true ]] || fatal 'stunnel listener did not become ready'
fi
unset master_password

printf '%s %s\n' "$vault_pid" "$tunnel_pid" >"$supervisor_dir/processes"

set +e
child_pids=("$vault_pid")
if [[ -n "$tunnel_pid" ]]; then
    child_pids+=("$tunnel_pid")
fi
wait -n "${child_pids[@]}"
child_status=$?
set -e
trap - TERM INT
cleanup_children

# Neither long-running child should exit successfully while this service is
# meant to be available. Turn an unexpected clean exit into a container error
# so Railway restarts the single instance and reports the failure.
if [[ "$child_status" -eq 0 ]]; then
    child_status=1
fi
exit "$child_status"
