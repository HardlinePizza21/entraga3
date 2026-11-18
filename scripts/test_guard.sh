#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ ! -x "$ROOT/build/mmap_guard" ] ||
   [ ! -x "$ROOT/build/mmap_guard_test" ]; then
    echo "Faltan los binarios. Ejecuta 'make' primero." >&2
    exit 1
fi

sudo -n "$ROOT/build/mmap_guard" --seconds 15 &
loader_pid=$!

cleanup() {
    wait "$loader_pid" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

sleep 2
if ! kill -0 "$loader_pid" 2>/dev/null; then
    echo "El cargador no sigue activo; revisa los mensajes de BPF LSM." >&2
    exit 1
fi

"$ROOT/build/mmap_guard_test"
wait "$loader_pid"
