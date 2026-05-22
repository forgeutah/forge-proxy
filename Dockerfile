# syntax=docker/dockerfile:1.7

# --- build stage --------------------------------------------------------------
# Pin --platform to $BUILDPLATFORM (the host running docker buildx) and let
# Go cross-compile to $TARGETARCH/$TARGETOS. The alternative — emulating the
# target arch via qemu — works but takes ~5 minutes per arch in CI; native
# cross-compile from amd64 to arm64 takes ~30s. CGO off makes this free.
#
# Alpine is small enough to pull quickly and ships current Go toolchains. Pin
# to 1.25 to match go.mod; bump both in lockstep.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

# Dependency layer: copying go.mod / go.sum first lets the layer cache survive
# source-only changes (the common case).
COPY go.mod go.sum ./
RUN go mod download

# Source + build. modernc.org/sqlite is pure Go so CGO stays off; the result
# is a static binary that runs anywhere the target kernel does. -trimpath
# keeps build-host paths out of the binary; -s -w drops the symbol table for
# a smaller image.
COPY . .
ENV CGO_ENABLED=0
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/forge-proxy ./cmd/forge-proxy

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
