#!/usr/bin/env bash
#
# Запуск веб-интерфейса osint-forge (Go-сервер на порту 8081).
#
#   ./start.sh            собрать при необходимости и запустить → http://localhost:8081
#   ./start.sh build      (пере)собрать фронтенд и бинарник сервера
#   ./start.sh dev        dev-сервер Vite (горячая перезагрузка) с проксированием на Go API
#   ./start.sh help       показать эту справку
#
# Остальные аргументы передаются бинарнику, например:
#   ./start.sh run -addr 0.0.0.0:8081   (доступ из локальной сети — авторизации нет, осторожно)
#   ./start.sh run -open                (автоматически открыть браузер)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/build/bin/osint-forge"
cd "$SCRIPT_DIR"

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "❌ '$1' не найден — для сборки нужен $2." >&2; exit 1; }
}

build() {
  need go "Go 1.26+ (https://go.dev)"
  need npm "Node.js + npm (https://nodejs.org)"
  echo "🔨 сборка фронтенда…"
  (cd frontend && { [ -d node_modules ] || npm install --no-audit --no-fund; } && npm run build)
  echo "🔨 сборка Go-сервера…"
  mkdir -p build/bin
  go build -o "$BIN" .
  echo "✅ Готово: $BIN"
}

# stale: true when there is no binary yet or any Go/UI source is newer than it
# (otherwise `./start.sh` kept running an old build after the code changed).
stale() {
  [ -x "$BIN" ] || return 0
  [ -n "$(find . \( -path ./frontend/node_modules -o -path ./build -o -path ./.git \) -prune -o \
      \( -name '*.go' -o -name go.mod -o -name go.sum -o -name '*.json' -path './internal/*' \) \
      -newer "$BIN" -print -quit)" ] && return 0
  [ -n "$(find frontend/src frontend/index.html frontend/package.json frontend/vite.config.ts \
      -newer "$BIN" -print -quit 2>/dev/null)" ] && return 0
  return 1
}

cmd="${1:-run}"; shift || true
case "$cmd" in
  build) build ;;
  run|"")
    if stale; then
      if command -v go >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
        build
      elif [ -x "$BIN" ]; then
        echo "⚠ исходники новее бинарника, но go/npm не найдены — запускается старая сборка." >&2
      else
        build # fails with a clear message about the missing tool
      fi
    fi
    exec "$BIN" "$@"
    ;;
  dev)
    stale && build
    "$BIN" "$@" &
    trap 'kill $! 2>/dev/null' EXIT
    cd frontend && npm run dev
    ;;
  # Only the header block (up to `set -euo`), without the shebang line.
  help|-h|--help) sed -n '2,/^set -euo/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//' ;;
  *) echo "Неизвестная команда: $cmd  (./start.sh [run|build|dev|help])" >&2; exit 1 ;;
esac
