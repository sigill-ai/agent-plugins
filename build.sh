#!/bin/sh
# Cross-compiles sigill-hook into the plugin. Pure Go, no cgo.
#
# The build is reproducible: the same source and Go toolchain produce byte-identical
# binaries on any machine. CI rebuilds on every push and fails if the committed binaries
# or SHA256SUMS differ, so what you install is what this source compiles to.
set -e
VERSION=${VERSION:-0.2.0}
OUT=plugins/sigill-evidence/libexec
want=$(sed -n 's/^toolchain //p' go.mod)
have=$(go env GOVERSION)
if [ "$have" != "$want" ]; then
  echo "build.sh: need $want for a reproducible build, have $have" >&2
  exit 1
fi
for target in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64; do
  os=${target%/*}; arch=${target#*/}
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false \
    -ldflags "-s -w -buildid= -X github.com/sigill-ai/claude-plugins/internal/sigill.Version=$VERSION" \
    -o "$OUT/sigill-hook-$os-$arch" ./cmd/sigill-hook
done
(cd "$OUT" && sha256sum sigill-hook-*-* > SHA256SUMS 2>/dev/null || shasum -a 256 sigill-hook-*-* > SHA256SUMS)
cat "$OUT/SHA256SUMS"
