# syntax=docker/dockerfile:1.7

# --- Builder stage: compile the Go binary
FROM golang:1.22-bookworm AS builder
WORKDIR /src

# Enable Go modules and cache deps
COPY go.mod ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Copy source and build
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w" -o /app/wiredolphin

# --- Build traffic_tunnel from provided sources in ./tunnel
FROM debian:bookworm-slim AS tunnel-builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
     build-essential make gcc \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build/tunnel
COPY /traffic_tunnel .
RUN make

# --- Runtime stage: minimal Debian with tools used by TUI and networking
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
     ca-certificates tzdata \
     net-tools iproute2 iputils-ping iptables \
     ncurses-bin bash \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /logs
RUN mkdir -p /app /logs
COPY --from=builder /app/wiredolphin /app/wiredolphin
COPY --from=tunnel-builder /build/tunnel/traffic_tunnel /usr/local/bin/traffic_tunnel
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Default interface can be overridden with IFACE env
ENV IFACE=tun0 \
    TUN_UNDERLAY_IF=eth0 \
    TUN_START=true \
    TUN_WAIT_TIMEOUT=20 \
    TUN_ADDR_CIDR=172.31.66.1/24 \
    TUN_ENABLE_NAT=true

# The app writes CSV logs to the CWD; docker-compose mounts a volume here
ENTRYPOINT ["/entrypoint.sh"]
