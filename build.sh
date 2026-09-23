#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v go >/dev/null 2>&1; then
    echo "[X] Go is not installed."
    exit 1
fi
go mod tidy >/dev/null 2>&1 || true
rm -f cleanip
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o cleanip .
echo "Done: $(pwd)/cleanip"
