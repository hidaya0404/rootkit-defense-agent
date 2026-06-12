#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v rootrap >/dev/null 2>&1; then
  exec rootrap "$@"
fi

if [ -x "$SCRIPT_DIR/rootrap.sh" ]; then
  exec "$SCRIPT_DIR/rootrap.sh" "$@"
fi

echo "rootrap is not installed. Run: sudo ./install.sh" >&2
exit 1
