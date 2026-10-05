# Build from the repository root:
# docker build -f examples/mutual-tls-container/Dockerfile -t agent-vault-mtls .

# ---- Frontend build ----
FROM node:26-alpine@sha256:2d984a15c9b54fd0aeb608b8e0d0d83529eb34d2966db27a1fb4f1edc3d298a3 AS frontend

WORKDIR /app
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ .
RUN npm run build

# ---- Go build stage ----
FROM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG POSTHOG_API_KEY=

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /internal/server/webdist /src/internal/server/webdist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w \
    -X github.com/Infisical/agent-vault/cmd.version=${VERSION} \
    -X github.com/Infisical/agent-vault/cmd.commit=${COMMIT} \
    -X github.com/Infisical/agent-vault/cmd.date=${BUILD_DATE} \
    -X github.com/Infisical/agent-vault/cmd.posthogAPIKey=${POSTHOG_API_KEY}" \
    -o /agent-vault .

# ---- Runtime stage ----
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk add --no-cache bash ca-certificates stunnel su-exec \
    && addgroup -S agentvault && adduser -S -G agentvault -u 65532 agentvault \
    && mkdir -p /data/.agent-vault && chown -R agentvault:agentvault /data

COPY --from=builder /agent-vault /usr/local/bin/agent-vault
COPY examples/mutual-tls-container/entrypoint.sh /usr/local/bin/mtls-entrypoint.sh
COPY examples/mutual-tls-container/healthcheck.sh /usr/local/bin/mtls-healthcheck.sh
RUN chmod +x /usr/local/bin/mtls-entrypoint.sh /usr/local/bin/mtls-healthcheck.sh

ENV HOME=/data
EXPOSE 14443
# Start as root to initialize the mounted volume, then drop both children.
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD ["/usr/local/bin/mtls-healthcheck.sh"]

ENTRYPOINT ["/usr/local/bin/mtls-entrypoint.sh"]
CMD ["server", "--host", "127.0.0.1", "--port", "14321", "--mitm-port", "14322"]
