# VRAM Copy Notes

The active split-VBlank VRAM copy queue uses `$FFAE-$FFB2`.

| Address | Name | Evidence |
|---------|------|----------|
| `$FFAE` | `VRAM_COPY_BLOCKS` | `VRAMCopySetup` writes the pending 16-byte block count. `VBlankHandler` calls `VRAMCopyDMA`, which returns immediately when this byte is zero. |
| `$FFAF-$FFB0` | `VRAM_SRC_LO` / `VRAM_SRC_HI` | `VRAMCopySetup` stores `DE` here. `VRAMCopyDMA` loads the pair into `SP`, then pops source words while copying to VRAM. |
| `$FFB1-$FFB2` | `VRAM_DST_LO` / `VRAM_DST_HI` | `VRAMCopySetup` stores `HL` here. `VRAMCopyDMA` uses the pair as the VRAM destination and writes back the advanced destination. |

`VRAMCopySetup` schedules at most `VRAM_COPY_MAX_BLOCKS_PER_VBLANK` (eight)
16-byte blocks per VBlank. For longer copies, it loops, waits for each VBlank,
then schedules the next chunk through the same primary queue.
`WaitVBlank` stores `VBLANK_SYNC_REQUESTED` in `VBLANK_SYNC` and halts in
`WaitVBlankSyncLoop` until the VBlank handler clears the sync byte.
`CopyQueuedVram16ByteBlockLoop` is the VBlank-side inner loop that pops and
writes one 16-byte block, then advances the saved source/destination pointers.

`SetupOAMDMA` is separate from the VRAM copy queue. It copies the ten-byte
`OAMDMARoutine` into HRAM through `CopyOAMDMARoutineToHRAMLoop`; VBlank later
calls the HRAM copy to DMA `SHADOW_OAM` into hardware OAM. The copied routine
writes `SHADOW_OAM_HI` to `rDMA`, waits `OAM_DMA_WAIT_LOOP_COUNT` decrements,
then returns.

Startup uses `BeginHardwareTilemapFill` / `FillHardwareTilemapLoop` to clear
the two `HARDWARE_TILEMAP_SIZE` hardware tilemaps selected by `SCRN0_HI` and
`SCRN1_HI` before normal runtime BG-map shadow copies begin. The clear tile is
named `HARDWARE_TILEMAP_CLEAR_TILE`.

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

## BG Map Shadow Direct Copy

`CopyNextBgMapShadowSlice` copies the always-live BG map shadow buffer separately from
the queued `VRAMCopyDMA` path. When `BG_MAP_SHADOW_COPY_ENABLE_FLAG` is
nonzero, it copies one six-row slice per VBlank and rotates
`BG_MAP_COPY_PHASE` (`$FFA6`) through `BG_MAP_COPY_PHASE_SLICE_0`,
`BG_MAP_COPY_PHASE_SLICE_1`, and `BG_MAP_COPY_PHASE_SLICE_2`.

| Source | Destination | Rows |
|--------|-------------|------|
| `BG_MAP_SHADOW_COPY_SLICE_0` (`$C4A0`) | `BG_MAP_VRAM_COPY_SLICE_0` (`$9C00`) | 0-5 |
| `BG_MAP_SHADOW_COPY_SLICE_1` (`$C518`) | `BG_MAP_VRAM_COPY_SLICE_1` (`$9CC0`) | 6-11 |
| `BG_MAP_SHADOW_COPY_SLICE_2` (`$C590`) | `BG_MAP_VRAM_COPY_SLICE_2` (`$9D80`) | 12-17 |

The shadow rows store the visible 20 tile bytes (`BG_MAP_ROW_STRIDE`), while
hardware BG map rows are 32 bytes (`BG_MAP_VRAM_ROW_STRIDE`). The loop saves
SP in `VBLANK_SAVED_SP_HI/LO`, temporarily points SP at the shadow slice, and
uses repeated `pop de` pairs to write each visible row into VRAM.
`SelectBgMapShadowCopySlice0` and `SelectBgMapShadowCopySlice1` name the first
two phase branches; the fall-through branch selects slice 2. The selected phase
is stored by `StoreNextBgMapShadowCopyPhase`, then
`CopyBgMapShadowSliceRowLoop` copies six visible rows before restoring SP.
