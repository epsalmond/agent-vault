# Mutual-TLS container example

This optional image wraps Agent Vault's proxy with stunnel client-certificate
authentication. Use it for a single-instance SQLite deployment with persistent
storage at `/data`. The API and raw proxy remain on loopback (`14321`/`14322`);
only the mTLS proxy listens externally, on `14443`.

The standard root Dockerfile does not run this wrapper and continues to
support the server's normal PostgreSQL, passwordless and credential-store
configuration. Keep its proxy on a trusted/private network.

## Build and run

From the repository root:

```sh
docker build -f examples/mutual-tls-container/Dockerfile -t agent-vault-mtls .
docker run --name agent-vault-mtls -p 14443:14443 \
  -v agent-vault-data:/data --env-file /path/to/private/container.env \
  agent-vault-mtls
```

Supply these inputs through your secret manager or a private, uncommitted
environment file:

| Variable | Meaning |
| --- | --- |
| `AGENT_VAULT_MASTER_PASSWORD` | Required master password for credential encryption |
| `AGENT_VAULT_MTLS_ENABLED` | Required `true` or `false`; use `true` for remote proxy access |
| `AGENT_VAULT_MTLS_SERVER_CERT_B64` | Base64 PEM server certificate/chain; required when enabled |
| `AGENT_VAULT_MTLS_SERVER_KEY_B64` | Base64 PEM server private key; required when enabled |
| `AGENT_VAULT_MTLS_CLIENT_TRUST_BUNDLE_B64` | Base64 PEM client-certificate trust bundle; required when enabled |
| `AGENT_VAULT_ADDR` | Broker address used for generated links; it does not expose the loopback API |

Issue certificates separately, including the server's hostname in its SANs,
and configure proxy clients to trust the server certificate and present a
client certificate. mTLS is in addition to the existing Agent Vault token and
vault authentication. It does not replace the client's trust in the Agent
Vault MITM CA for intercepted upstream TLS.

With `AGENT_VAULT_MTLS_ENABLED=false`, no external proxy listener is started;
that mode is for local bootstrap or diagnostics. Access the loopback management
API through a separately secured administrative path. This example does not
expose a public management UI.

## Runtime constraints

The entrypoint starts as root to initialize mounted-volume ownership, then
launches Agent Vault and stunnel as `agentvault` (UID 65532). Transport keys
are written privately to ephemeral storage and removed from child environments.
Do not override the server's loopback host or fixed listener ports.

The wrapper rejects PostgreSQL, Infisical credential-store integration,
development mode and private upstream allowlists. Use the standard image when
those configurations are needed. Health checks require the API and raw proxy,
plus stunnel when enabled. Either long-running child exiting stops the container;
configure restarts in your container runtime.

## Migration from the earlier bundled image

The repository's root Dockerfile now uses the standard entrypoint, not this
transport wrapper. A default rebuild changes the exposed ports and no longer
starts stunnel. Before replacing an image that relied on the bundled wrapper,
change the build to the explicit example Dockerfile above. Retain the `/data`
mount, password and transport inputs; verify client-certificate enforcement
before routing traffic to the replacement. No running deployment is changed
by this source cleanup.

The earlier `ARCADE_VAULT_MTLS_*` names remain accepted as input aliases for
the four corresponding `AGENT_VAULT_MTLS_*` variables. Canonical values take
precedence, including explicit empty values (which fail required-input checks).
Legacy inputs are removed before children start. Update deployment settings to
the canonical names when convenient; no merged Git history needs rewriting.

## Local checks

```sh
bash -n examples/mutual-tls-container/{entrypoint,healthcheck}.sh
examples/mutual-tls-container/test-inputs.sh
```

The input checks exercise configuration validation with fixtures, without
starting services or touching mounted storage. They do not prove certificate
validation, privilege dropping, or readiness in a built container; validate
those on an isolated deployment before promotion.
