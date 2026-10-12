#!/bin/sh
# Local development without writing binaries to the host: sources are copied into a Docker
# volume and built/tested there. Endpoint scanners flag every freshly written, unsigned binary,
# and the plugin's binaries are rebuilt often; CI builds and commits the shipped ones.
#
#   ./dev.sh test    go vet + go test -race
#   ./dev.sh build   cross-compile all four binaries inside the volume and print their SHA-256
#   ./dev.sh local   build only this machine's binary and copy it into libexec/ (for a real
#                    Claude Code run with --plugin-dir; never commit it — CI owns the binaries)
#   ./dev.sh shell   a shell in the build volume
set -e
cd "$(dirname "$0")"
GO=$(sed -n 's/^toolchain go//p' go.mod)
IMG="golang:$GO"
LIBEXEC=plugins/sigill-evidence/libexec

in_volume() { # $1: command to run in /w after a fresh copy of the sources; $2: extra docker args
	docker run --rm -i $2 -v "$PWD":/src:ro -v sigill-plugin-build:/w -v sigill-plugin-gocache:/root/go -w /w "$IMG" sh -c "
		git config --global --add safe.directory /w
		find /w -mindepth 1 -delete
		cd /src && tar --exclude=./.git --exclude='./$LIBEXEC/sigill-hook-*-*' --exclude=./$LIBEXEC/SHA256SUMS -cf - . | tar -xf - -C /w
		cd /w && $1"
}

case "${1:-test}" in
test)  in_volume 'go vet ./... && go test -race ./...' ;;
build) in_volume 'sh build.sh' ;;
local)
	os=$(uname -s | tr '[:upper:]' '[:lower:]')
	arch=$(uname -m); case "$arch" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
	in_volume "VERSION=\$(sed -n 's/.*\"version\": \"\\(.*\\)\".*/\\1/p' plugins/sigill-evidence/.claude-plugin/plugin.json) && \
		CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false \
		-ldflags \"-s -w -buildid= -X github.com/sigill-ai/agent-plugins/internal/sigill.Version=\$VERSION\" \
		-o /out/sigill-hook-$os-$arch ./cmd/sigill-hook" "-v $PWD/$LIBEXEC:/out"
	echo "built $LIBEXEC/sigill-hook-$os-$arch (do not commit; CI builds the shipped binaries)" ;;
shell) in_volume 'sh' "-t" ;;
*) echo "usage: ./dev.sh [test|build|local|shell]" >&2; exit 2 ;;
esac
