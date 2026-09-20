# Multi-stage build for the tokyo3-veilgate project.
#
# The final server image contains only the statically linked veilgated binary
# and the licence. Build with `--target server` for the runtime image.

# ── Stage 1: Build veilgated ──────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=arm64
ARG VERSION=dev

WORKDIR /src

# Download dependencies before copying source so this layer remains cached.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" \
    -o /out/veilgated ./cmd/veilgated

# ── Stage 2: Server runtime image ─────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot AS server

ARG VERSION=dev
LABEL org.opencontainers.image.title="Veilgate" \
      org.opencontainers.image.description="Secret-aware egress gateway for agent sandboxes" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder --chown=nonroot:nonroot /out/veilgated /usr/local/bin/veilgated
COPY --chown=nonroot:nonroot LICENSE /licenses/veilgate/LICENSE

EXPOSE 8080 8081
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/veilgated"]
CMD ["serve"]
