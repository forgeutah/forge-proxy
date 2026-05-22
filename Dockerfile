# syntax=docker/dockerfile:1.7

# --- build stage --------------------------------------------------------------
# Alpine is small enough to pull quickly and ships current Go toolchains. We
# pin to 1.25 to match the go.mod declared version; bump both in lockstep.
FROM golang:1.25-alpine AS build
WORKDIR /src

# Dependency layer: copying go.mod / go.sum first lets the layer cache survive
# source-only changes (the common case).
COPY go.mod go.sum ./
RUN go mod download

# Source + build. modernc.org/sqlite is pure Go so CGO stays off; the result
# is a static binary that runs anywhere a Linux kernel does. -trimpath keeps
# build-host paths out of the binary; -s -w drops the symbol table for a
# smaller image.
COPY . .
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/forge-proxy ./cmd/forge-proxy

# --- runtime stage ------------------------------------------------------------
# distroless/static is the smallest possible base for a static Go binary: no
# shell, no package manager, no userland — just glibc-style loader stubs and
# a non-root user. The :nonroot tag pre-creates uid/gid 65532. Trade-off:
# `docker exec ... sh` is unavailable; admin CLI invocations run the binary
# directly (`docker exec ... forge-proxy admin ...`).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/forge-proxy /usr/local/bin/forge-proxy

# The default HTTP port; override at runtime via LISTEN_ADDR=:N if needed.
EXPOSE 8080

# Run as the pre-baked nonroot user (uid/gid 65532). The persistent disk mount
# at /data must be writable by this uid — see README's first-time-deploy.
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/forge-proxy"]
