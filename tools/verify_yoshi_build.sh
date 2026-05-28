#!/bin/sh
set -eu

EXPECTED_SHA256="970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253"
EXPECTED_SIZE="65536"
EXPECTED_TITLE_HEX="594f535359204e4f2054414d41474f00"
EXPECTED_CART_TYPE="01"
EXPECTED_ROM_SIZE="01"
EXPECTED_RAM_SIZE="00"
EXPECTED_HEADER_CHECKSUM="a7"

fail() {
    echo "verify_yoshi_build: $*" >&2
    exit 1
}

repo_root() {
    CDPATH= cd -- "$(dirname -- "$0")/.." && pwd
}

file_size() {
    wc -c < "$1" | tr -d ' '
}

sha256() {
    shasum -a 256 "$1" | awk '{print $1}'
}

bytes_hex() {
    dd if="$1" bs=1 skip="$2" count="$3" 2>/dev/null \
        | od -An -tx1 \
        | tr -d ' \n'
}

check_rom() {
    rom="$1"

    [ -f "$rom" ] || fail "$rom is missing"
    [ "$(file_size "$rom")" = "$EXPECTED_SIZE" ] || fail "$rom size mismatch"
    [ "$(sha256 "$rom")" = "$EXPECTED_SHA256" ] || fail "$rom SHA-256 mismatch"
    [ "$(bytes_hex "$rom" 308 16)" = "$EXPECTED_TITLE_HEX" ] || fail "$rom title mismatch"
    [ "$(bytes_hex "$rom" 327 1)" = "$EXPECTED_CART_TYPE" ] || fail "$rom cartridge type mismatch"
    [ "$(bytes_hex "$rom" 328 1)" = "$EXPECTED_ROM_SIZE" ] || fail "$rom ROM size header mismatch"
    [ "$(bytes_hex "$rom" 329 1)" = "$EXPECTED_RAM_SIZE" ] || fail "$rom RAM size header mismatch"
    [ "$(bytes_hex "$rom" 333 1)" = "$EXPECTED_HEADER_CHECKSUM" ] || fail "$rom header checksum mismatch"
}

ROOT="$(repo_root)"
cd "$ROOT"

command -v git >/dev/null 2>&1 || fail "git not found"
command -v make >/dev/null 2>&1 || fail "make not found"
command -v rg >/dev/null 2>&1 || fail "rg not found"
command -v shasum >/dev/null 2>&1 || fail "shasum not found"
command -v awk >/dev/null 2>&1 || fail "awk not found"
command -v od >/dev/null 2>&1 || fail "od not found"
command -v dd >/dev/null 2>&1 || fail "dd not found"

git diff --check

cd "$ROOT/Yoshi"
make -B
cmp -s yoshi.gb game.gb || fail "rebuilt game.gb differs from yoshi.gb"

cd "$ROOT"
check_rom Yoshi/yoshi.gb
check_rom Yoshi/game.gb

if ! git diff --quiet -- Yoshi/game.sym Yoshi/game.map Yoshi/game.gb; then
    fail "generated Yoshi outputs have tracked diffs"
fi

if rg -n 'call \$|jp \$|jr \$' Yoshi/bank_000.asm Yoshi/bank_001.asm; then
    fail "raw direct branch operand found"
fi

echo "verify_yoshi_build: OK"
