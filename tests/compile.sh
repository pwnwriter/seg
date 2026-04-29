#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$DIR/bins"
mkdir -p "$BIN_DIR"

echo "Compiling test binaries into $BIN_DIR..."

# bof_basic: classic buffer overflow, no canary, no PIE
cc -Wno-deprecated-declarations -fno-stack-protector -o "$BIN_DIR/bof_basic" "$DIR/bof_basic.c"
echo "  bof_basic"

# fmt_string: format string vulnerability
cc -Wno-format-security -o "$BIN_DIR/fmt_string" "$DIR/fmt_string.c"
echo "  fmt_string"

# ret2libc: ret2libc target, no canary
cc -fno-stack-protector -o "$BIN_DIR/ret2libc" "$DIR/ret2libc.c"
echo "  ret2libc"

# heap_uaf: use-after-free / heap challenge
cc -o "$BIN_DIR/heap_uaf" "$DIR/heap_uaf.c"
echo "  heap_uaf"

echo "Done. Binaries in $BIN_DIR/"
