#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BUILD=$(mktemp -d)
trap 'rm -rf -- "$BUILD"' EXIT
export GOTOOLCHAIN=go1.27.3 CGO_ENABLED=0 GOMAXPROCS=2
git clone --quiet https://github.com/hackdiaz-dev/free-turn-proxy.git "$BUILD/source"
cd "$BUILD/source"
git checkout --quiet 6d857e1e847a38fdee3e150314fb37009e3c37a6
git apply "$ROOT/third_party/freeturn-keyfile.patch"
cp "$ROOT/third_party/freeturn-go-mod" go.mod
cp "$ROOT/third_party/freeturn-go-sum" go.sum
go mod verify
go test -p 2 ./internal/config ./internal/clientsdb ./internal/wire/... ./internal/proxy/udpserver ./cmd/server
mkdir -p "$ROOT/artifacts"
for ARCH in amd64 arm64; do
  GOOS=linux GOARCH=$ARCH go build -p 2 -trimpath \
    -ldflags='-s -w -checklinkname=0 -X main.version=4.1.2-vps1' \
    -o "$ROOT/artifacts/freeturn-linux-$ARCH" ./cmd/server
done
echo 'Compare sha256sum artifacts/freeturn-linux-* with artifacts/manifest.json.'
