##= BUILDER =##
# Build a fully static (musl) binary so the runtime image needs nothing but a
# CA bundle. Mirrors the static Linux release binary in release-binary.yml.
FROM crystallang/crystal:1.20.0-alpine AS builder
WORKDIR /authz0

# authz0 links against OpenSSL (HTTPS scanning) and libyaml (templates/exports);
# the *-static archives let `crystal build --static` fold them into the binary.
RUN apk add --no-cache \
    git \
    yaml-dev yaml-static \
    openssl-dev openssl-libs-static \
    zlib-dev zlib-static \
    pcre2-dev

COPY shard.yml shard.lock ./
# Zero runtime deps, but keep the step so the image layer-caches like any shard.
RUN shards install --production

COPY . .
RUN crystal build src/main.cr -o /authz0/authz0 --release --no-debug --static && \
    strip /authz0/authz0

##= RUNNER =##
FROM alpine:3.20

# Standard OCI labels
LABEL org.opencontainers.image.title="authz0"
LABEL org.opencontainers.image.description="Automated authorization (access-control) testing tool written in Crystal."
LABEL org.opencontainers.image.authors="HAHWUL <hahwul@gmail.com>"
LABEL org.opencontainers.image.source="https://github.com/hahwul/authz0"
LABEL org.opencontainers.image.documentation="https://github.com/hahwul/authz0"
LABEL org.opencontainers.image.licenses="MIT"

# GitHub Action labels
LABEL "com.github.actions.name"="authz0 authorization scan"
LABEL "com.github.actions.description"="Run an authz0 authorization scan and emit SARIF/JSON."
LABEL "com.github.actions.icon"="shield"
LABEL "com.github.actions.color"="blue"

# ca-certificates is required for TLS verification (`scan --secure`); the static
# binary is otherwise self-contained.
RUN apk add --no-cache ca-certificates

COPY --from=builder /authz0/authz0 /usr/local/bin/authz0
COPY --chmod=755 docker/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
