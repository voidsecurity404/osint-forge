#!/usr/bin/env bash
#
# osint-forge launcher. Works from any shell (fish, zsh, bash) since it runs
# under bash itself.
#
#   ./start.sh            run the prebuilt app (builds it first if missing)
#   ./start.sh dev        run in dev mode with hot reload (needs Go + Wails)
#   ./start.sh build      (re)build the production binary
#   ./start.sh help       show this help
#
set -euo pipefail

# Project directory = where this script lives (robust if you move the project).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/build/bin/osint-forge"
TAGS="webkit2_41"   # required on Arch/Omarchy: only webkit2gtk-4.1 exists

cd "$SCRIPT_DIR"

# Put the Go toolchain and the Wails CLI on PATH (via mise). Only needed for
# dev/build, not for simply running the prebuilt binary.
setup_toolchain() {
  if command -v mise >/dev/null 2>&1; then
    eval "$(mise activate bash)" 2>/dev/null || true
  fi
  if command -v go >/dev/null 2>&1; then
    export PATH="$(go env GOBIN):$PATH"
  fi
  if ! command -v wails >/dev/null 2>&1; then
    echo "❌ 'wails' topilmadi. O'rnatish: go install github.com/wailsapp/wails/v2/cmd/wails@latest" >&2
    exit 1
  fi
}

case "${1:-run}" in
  dev)
    setup_toolchain
    echo "🚀 dev rejim (hot reload)…"
    exec wails dev -tags "$TAGS"
    ;;
  build)
    setup_toolchain
    echo "🔨 build qilinmoqda…"
    wails build -tags "$TAGS"
    echo "✅ Tayyor: $BIN"
    ;;
  run|"")
    if [ ! -x "$BIN" ]; then
      echo "ℹ️  Binary topilmadi — build qilinmoqda…"
      setup_toolchain
      wails build -tags "$TAGS"
    fi
    echo "🚀 Ishga tushmoqda: $BIN"
    exec "$BIN"
    ;;
  help|-h|--help)
    grep '^#' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    echo "Noma'lum buyruq: $1  (ishlatish: ./start.sh [run|dev|build|help])" >&2
    exit 1
    ;;
esac
