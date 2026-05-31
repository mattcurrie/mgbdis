# YOSSY NO TAMAGO GB Source Recovery Baseline

This document records the current evidence baseline for source recovery. Treat `Yoshi/yoshi.gb` as the preserved ROM unless stronger evidence is found.

## Preserved ROM

| File | Size | SHA-256 | Notes |
|------|------|---------|-------|
| `Yoshi/yoshi.gb` | 65,536 bytes | `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` | Tracked preserved ROM |
| `Yoshi/game.gb` | 65,536 bytes | `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` | Ignored build output, currently byte-identical |

`cmp -s Yoshi/yoshi.gb Yoshi/game.gb` returns exit code `0`.

## Header Facts

Both `Yoshi/yoshi.gb` and rebuilt `Yoshi/game.gb` currently report:

| Field | Offset | Value | Meaning |
|-------|--------|-------|---------|
| Title | `$0134-$0143` | `YOSSY NO TAMAGO` | Japanese/internal title string |
| New licensee code | `$0144-$0145` | `$00 $00` | Unused because the old licensee code is not `$33` |
| SGB flag | `$0146` | `$00` | No Super Game Boy support flag |
| Cartridge type | `$0147` | `$01` | MBC1 |
| ROM size | `$0148` | `$01` | 64KB |
| RAM size | `$0149` | `$00` | No external RAM |
| Destination code | `$014A` | `$00` | Japan |
| Old licensee code | `$014B` | `$01` | Nintendo |
| Mask ROM version | `$014C` | `$00` | Version 0 |
| Header checksum | `$014D` | `$A7` | Valid after `rgbfix` |
| Global checksum | `$014E-$014F` | `$97 $A1` | Full ROM checksum bytes |

## Rebuild Status

`Yoshi/Makefile` builds the source through RGBDS:

```text
rgbasm -o game.o game.asm
rgblink -n game.sym -m game.map -o game.gb game.o
rgbfix -v -p 255 game.gb
```

On 2026-05-28, `make -B` completed successfully with installed RGBDS tools:

```text
/opt/homebrew/bin/rgbasm
/opt/homebrew/bin/rgblink
/opt/homebrew/bin/rgbfix
/opt/homebrew/bin/rgbgfx
```

The rebuilt `Yoshi/game.gb` matches `Yoshi/yoshi.gb` byte-for-byte after the forced rebuild.

The repository also contains `tools/verify_yoshi_build.sh`, which reruns the
current recovery gate:

- `git diff --check`
- forced `Yoshi` rebuild
- byte-for-byte `yoshi.gb` / `game.gb` comparison
- ROM size, SHA-256, and key header byte checks
- generated artifact cleanliness check
- raw direct branch scan for `call $`, `jp $`, and `jr $`

## Tracked vs Generated Files

Tracked source/baseline files include:

- `Yoshi/yoshi.gb`
- `Yoshi/game.asm`
- `Yoshi/bank_000.asm`
- `Yoshi/bank_001.asm`
- `Yoshi/bank_002.asm`
- `Yoshi/bank_003.asm`
- `Yoshi/constants.inc`
- `Yoshi/hardware.inc`
- `Yoshi/yoshi.sym`
- `Yoshi/ARCHITECTURE.md`
- `Yoshi/SERIAL_PROTOCOL.md`
- `Yoshi/Makefile`

Ignored build outputs:

- `Yoshi/game.gb`
- `Yoshi/game.o`
- `Yoshi/game.sym`
- `Yoshi/game.map`

## Bank Layout

| Bank | Source file | CPU window | Role |
|------|-------------|------------|------|
| 0 | `Yoshi/bank_000.asm` | `$0000-$3FFF` fixed ROM0 | Entry, interrupts, main loop, state machine, core gameplay/UI |
| 1 | `Yoshi/bank_001.asm` | `$4000-$7FFF` switch ROMX | Normal active switch bank: VBlank, sprites, sound, link, helper logic/data |
| 2 | `Yoshi/bank_002.asm` | `$4000-$7FFF` switch ROMX | Graphics/tile data copied into VRAM |
| 3 | `Yoshi/bank_003.asm` | `$4000-$7FFF` switch ROMX | Additional graphics/tile data copied into VRAM |

Observed runtime policy:

- `Init` selects Bank 1 early via `ld [$2100], a` with `a = $01`.
- Normal LCD-on execution expects Bank 1 to be active.
- VBlank entry jumps to Bank 1 code at `$4B59`.
- Bank 2/3 are selected temporarily while LCD is off or during controlled graphics-loading paths, then Bank 1 is restored.

Interrupt-sensitive bank audit:

- The only banked interrupt handler is VBlank: the ROM0 vector jumps into
  `VBlankHandler` in Bank 1. This path therefore relies on Bank 1 being the
  active switch bank whenever LCD-on VBlank interrupts can occur.
- The current source writes `MBC1_ROM_BANK_REG` only in the documented graphics
  load paths, `Init`, and the Bank 1 VBlank handler. All Bank 2/3 selections are
  paired with a restore to `ROM_BANK_MAIN_CODE` before LCD-on normal execution
  resumes.
- Title, pre-play, gameplay, matching/result, high-score/result-record, and
  link-result graphics loads select Bank 2 or Bank 3 only after `LCDOff` or
  within the LCD-off setup window, then restore Bank 1 before `LCDOn` or before
  returning to the frame loop.
- The serial interrupt vector and handler both live in ROM0, so serial
  handshakes do not depend on the current switch bank. The timer interrupt bit
  is enabled in `STARTUP_ENABLED_INTERRUPTS`, but `Init` leaves `rTAC` cleared;
  no timer ISR path is recovered as live code.
- `VBlankHandler` writes `ROM_BANK_MAIN_CODE` before the sprite/sound/timer tail
  of the handler, keeping the normal post-interrupt switch-bank invariant
  explicit.

## Recovery Invariants

- Behavior-preserving source edits must continue to rebuild to a ROM byte-identical to `Yoshi/yoshi.gb`, unless a deliberate, documented non-matching exploratory branch is used.
- Any comment or rename should be traceable to code evidence, ROM data, build output, or user testimony.
- Mis-disassembled data should be converted cautiously, with before/after rebuild comparison.
