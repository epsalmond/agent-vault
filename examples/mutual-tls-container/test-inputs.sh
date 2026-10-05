#!/usr/bin/env bash
set -euo pipefail

# Exercise the actual entrypoint preflight before filesystem initialization.
# Fake only its UID check; no services, certificate files or mounted paths run.
example_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
entrypoint_path=${1:-$example_dir/entrypoint.sh}
preflight=$(sed '/^umask 077$/,$d' "$entrypoint_path")
[[ "$preflight" != "$(<"$entrypoint_path")" ]] || { echo 'missing preflight boundary' >&2; exit 1; }
fixture_program=$'id() { printf "0\\n"; }\n'"$preflight"$'\n'
# These expressions expand in the fixture subprocess, not this test runner.
# shellcheck disable=SC2016
fixture_program+='[[ "$AGENT_VAULT_MTLS_ENABLED" == "$EXPECTED_MODE" ]]
[[ "$AGENT_VAULT_MTLS_SERVER_CERT_B64" == "${EXPECTED_CERT-}" ]]
[[ "$AGENT_VAULT_MTLS_SERVER_KEY_B64" == "${EXPECTED_KEY-}" ]]
[[ "$AGENT_VAULT_MTLS_CLIENT_TRUST_BUNDLE_B64" == "${EXPECTED_TRUST-}" ]]
for legacy_input in ARCADE_VAULT_MTLS_ENABLED ARCADE_VAULT_MTLS_SERVER_CERT_B64 ARCADE_VAULT_MTLS_SERVER_KEY_B64 ARCADE_VAULT_MTLS_CLIENT_TRUST_BUNDLE_B64; do
    [[ ! -v "$legacy_input" ]]
done'

check_case() {
    local label=$1 expected=$2 actual=0
    shift 2
    env -i PATH=/usr/bin:/bin AGENT_VAULT_MASTER_PASSWORD=fixture \
        EXPECTED_MODE=false "$@" bash -c "$fixture_program" -- server >/dev/null 2>&1 || actual=1
    if [[ "$actual" != "$expected" ]]; then
        printf 'FAIL: %s\n' "$label" >&2
        exit 1
    fi
}

check_case canonical-disabled 0 AGENT_VAULT_MTLS_ENABLED=false
check_case legacy-disabled 0 ARCADE_VAULT_MTLS_ENABLED=false
check_case canonical-switch-precedence 0 AGENT_VAULT_MTLS_ENABLED=false ARCADE_VAULT_MTLS_ENABLED=true
check_case explicit-empty-switch 1 AGENT_VAULT_MTLS_ENABLED= ARCADE_VAULT_MTLS_ENABLED=false
check_case missing-switch 1
check_case invalid-switch 1 AGENT_VAULT_MTLS_ENABLED=maybe
check_case missing-password 1 AGENT_VAULT_MTLS_ENABLED=false AGENT_VAULT_MASTER_PASSWORD=
check_case missing-certificates 1 AGENT_VAULT_MTLS_ENABLED=true
check_case canonical-enabled 0 AGENT_VAULT_MTLS_ENABLED=true ARCADE_VAULT_MTLS_ENABLED=false \
    AGENT_VAULT_MTLS_SERVER_CERT_B64=canonical-cert ARCADE_VAULT_MTLS_SERVER_CERT_B64=legacy-cert \
    AGENT_VAULT_MTLS_SERVER_KEY_B64=canonical-key ARCADE_VAULT_MTLS_SERVER_KEY_B64=legacy-key \
    AGENT_VAULT_MTLS_CLIENT_TRUST_BUNDLE_B64=canonical-trust ARCADE_VAULT_MTLS_CLIENT_TRUST_BUNDLE_B64=legacy-trust \
    EXPECTED_MODE=true EXPECTED_CERT=canonical-cert EXPECTED_KEY=canonical-key EXPECTED_TRUST=canonical-trust
check_case legacy-enabled 0 ARCADE_VAULT_MTLS_ENABLED=true \
    ARCADE_VAULT_MTLS_SERVER_CERT_B64=legacy-cert ARCADE_VAULT_MTLS_SERVER_KEY_B64=legacy-key \
    ARCADE_VAULT_MTLS_CLIENT_TRUST_BUNDLE_B64=legacy-trust \
    EXPECTED_MODE=true EXPECTED_CERT=legacy-cert EXPECTED_KEY=legacy-key EXPECTED_TRUST=legacy-trust
check_case explicit-empty-key 1 AGENT_VAULT_MTLS_ENABLED=true \
    AGENT_VAULT_MTLS_SERVER_CERT_B64=fixture-cert AGENT_VAULT_MTLS_SERVER_KEY_B64= \
    ARCADE_VAULT_MTLS_SERVER_KEY_B64=legacy-key AGENT_VAULT_MTLS_CLIENT_TRUST_BUNDLE_B64=fixture-trust
check_case postgres-rejected 1 AGENT_VAULT_MTLS_ENABLED=false DATABASE_URL=postgres://fixture
check_case infisical-rejected 1 AGENT_VAULT_MTLS_ENABLED=false INFISICAL_URL=https://fixture.invalid
check_case development-rejected 1 AGENT_VAULT_MTLS_ENABLED=false AGENT_VAULT_DEV_MODE=true
check_case private-ranges-rejected 1 AGENT_VAULT_MTLS_ENABLED=false AGENT_VAULT_ALLOW_PRIVATE_RANGES=true
check_case allowlist-rejected 1 AGENT_VAULT_MTLS_ENABLED=false AGENT_VAULT_NETWORK_ALLOWLIST=192.0.2.1
echo 'test-inputs: PASS (16 cases; preflight only)'
