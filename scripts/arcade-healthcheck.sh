#!/usr/bin/env bash
set -eu

wget -q -O /dev/null http://127.0.0.1:14321/health
exec 3<>/dev/tcp/127.0.0.1/14322

read -r vault_pid tunnel_pid mtls_enabled </tmp/agent-vault-supervisor/processes
kill -0 "$vault_pid"
if [ "$mtls_enabled" = true ]; then
    exec 4<>/dev/tcp/127.0.0.1/14443
    kill -0 "$tunnel_pid"
fi
