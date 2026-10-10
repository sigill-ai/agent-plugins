#!/bin/sh
# Cross-compiles sigill-hook into the plugin. Pure Go, no cgo.
set -e
VERSION=${VERSION:-0.1.0}
OUT=plugins/sigill-evidence/libexec
for target in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64; do
  os=${target%/*}; arch=${target#*/}
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
    -ldflags "-s -w -X github.com/sigill-ai/claude-plugins/internal/sigill.Version=$VERSION" \
    -o "$OUT/sigill-hook-$os-$arch" ./cmd/sigill-hook
done
ls -la "$OUT"
