#!/usr/bin/env bash
# Build the Go correlation-engine port (language-comparison study).
# Stdlib-only, so no module download is required.
set -euo pipefail
HERE=$(cd "$(dirname "$0")"/../../go_agent && pwd)
cd "$HERE"
go build -o langagent .
echo "built: $HERE/langagent"
"$HERE/langagent" --help 2>&1 | head -1 || true
