# syntax=docker/dockerfile:1.7

# --- Builder stage: compile the Go binary
FROM golang:1.22-bookworm AS builder
WORKDIR /src

# Enable Go modules and cache deps
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Copy source and build
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w" -o /app/wiredolphin

# --- Runtime stage: minimal Debian with tools used by TUI
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates tzdata \
      net-tools iproute2 iputils-ping \
      ncurses-bin \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /logs
RUN mkdir -p /app /logs
COPY --from=builder /app/wiredolphin /app/wiredolphin

# Default interface can be overridden with IFACE env
ENV IFACE=tun0

# The app writes CSV logs to the CWD; docker-compose mounts a volume here
ENTRYPOINT ["/bin/sh","-c","/app/wiredolphin ${IFACE}"]
