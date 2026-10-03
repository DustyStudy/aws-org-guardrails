# Builds the Claude apps gateway container image for the ECS Fargate
# deployment. Requires the linux-x64 glibc `claude` binary at ./claude in
# the build context - download a pinned release per
# https://code.claude.com/docs/en/setup - and a filled-in gateway.yaml
# (copy gateway.yaml.example and replace every REPLACE_ME) in the same
# directory.
#
# The RDS CA bundle is the trust anchor for store.postgres_url's
# sslmode=verify-full. Download it fresh for every build rather than
# pinning a checksum, since AWS periodically appends new regional CAs:
#
#   curl -fL --proto '=https' -o rds-global-bundle.pem \
#     https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
#
# Build (must match the task definition's RuntimePlatform - X86_64/LINUX
# by default in this stack's template; for Graviton/ARM64 change
# --platform here and RuntimePlatform.CpuArchitecture in the template):
#
#   docker build --platform=linux/amd64 \
#     -t "<account-id>.dkr.ecr.<region>.amazonaws.com/<stack-name>:<version>" .
#   docker push "<account-id>.dkr.ecr.<region>.amazonaws.com/<stack-name>:<version>"
#
# A config edit means a rebuild under a new tag - gateway.yaml is
# embedded into the image, and ECR's IMMUTABLE tag setting on the
# repository this stack creates means an existing tag can't be
# re-pointed at new content anyway.

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY claude /usr/local/bin/claude
RUN chmod +x /usr/local/bin/claude

COPY gateway.yaml /etc/claude/gateway.yaml
COPY rds-global-bundle.pem /etc/claude/rds-global-bundle.pem
ENV NODE_EXTRA_CA_CERTS=/etc/claude/rds-global-bundle.pem

# Run unprivileged; 8080 is above 1024 so no capabilities are needed.
RUN useradd --system --no-create-home --uid 10001 --shell /usr/sbin/nologin gateway
USER 10001

EXPOSE 8080

ENTRYPOINT ["claude", "gateway", "--config", "/etc/claude/gateway.yaml"]
