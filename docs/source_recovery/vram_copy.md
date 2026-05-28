# VRAM Copy Queue

The active split-VBlank VRAM copy queue uses `$FFAE-$FFB2`.

| Address | Name | Evidence |
|---------|------|----------|
| `$FFAE` | `VRAM_COPY_BLOCKS` | `VRAMCopySetup` writes the pending 16-byte block count. `VBlankHandler` calls `VRAMCopyDMA`, which returns immediately when this byte is zero. |
| `$FFAF-$FFB0` | `VRAM_SRC_LO` / `VRAM_SRC_HI` | `VRAMCopySetup` stores `DE` here. `VRAMCopyDMA` loads the pair into `SP`, then pops source words while copying to VRAM. |
| `$FFB1-$FFB2` | `VRAM_DST_LO` / `VRAM_DST_HI` | `VRAMCopySetup` stores `HL` here. `VRAMCopyDMA` uses the pair as the VRAM destination and writes back the advanced destination. |

`VRAMCopySetup` schedules at most eight 16-byte blocks per VBlank. For longer
copies, it loops, waits for each VBlank, then schedules the next chunk through
the same primary queue.

## Unused Secondary Slot

The bytes at `$FFB3-$FFB7` are now named `UNUSED_VRAM_COPY2_*`.

The ROM contains a second setup-shaped fragment at `00:$0244` that stores
`DE`, `HL`, and a block count into `$FFB3-$FFB7`, then calls `WaitVBlank`.
Current evidence shows it is not part of the live transfer path:

- No pre-existing symbol, call, jump, or fall-through path targets `00:$0244`.
- The preceding primary chunk loop either jumps back to `VRAMCopyNextChunk` or
  returns after scheduling the final primary chunk; it does not fall through to
  the secondary fragment.
- `VRAMCopyDMA`, the only VBlank VRAM copy routine currently called from
  `VBlankHandler`, reads `$FFAE-$FFB2` only.

This looks like a leftover or abandoned second-copy queue idea rather than an
active transfer path in the shipped ROM.
