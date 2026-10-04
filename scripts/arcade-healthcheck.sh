#!/bin/sh
set -eu

wget -q -O /dev/null http://127.0.0.1:14321/health

read -r vault_pid tunnel_pid </tmp/agent-vault-supervisor/processes
kill -0 "$vault_pid"
if [ -n "$tunnel_pid" ]; then
    kill -0 "$tunnel_pid"
fi
