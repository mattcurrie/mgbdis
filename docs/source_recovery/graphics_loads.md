# Graphics Bank Load Map

This document records the observed ROM-bank-to-VRAM graphics copies. Bank 1 is
the normal active switch bank; Bank 2 and Bank 3 are selected temporarily for
bulk graphics loads and then `ROM_BANK_MAIN_CODE` is restored.

## Banking Constants

| Symbol | Value | Meaning | Confidence |
|--------|-------|---------|------------|
| `MBC1_ROM_BANK_REG` | `$2100` | MBC1 ROM bank select write target used by this ROM. | High |
| `ROM_BANK_MAIN_CODE` | `$01` | Normal switch bank containing VBlank, sprites, sound, and cross-bank helpers. | High |
| `ROM_BANK_GRAPHICS_0` | `$02` | Graphics bank containing title/game/common/two-player tile sets. | High |
| `ROM_BANK_GRAPHICS_1` | `$03` | Additional graphics bank loaded during match/result/high-score flows. | High |

`VBlankHandler` also writes `ROM_BANK_MAIN_CODE` before calling `UpdateSprites`,
which supports the observation that Bank 1 is the expected active bank during
normal LCD-on execution.

## Bank 2 Loads

| Code path | Source | Destination | Size | Tiles | Notes |
|-----------|--------|-------------|------|-------|-------|
| `MainLoop` / `GAME_STATE_TITLE_INIT` | `GameTileSet` `$4000-$47FF` | `VRAM_TILE_BLOCK_8000` (`$8000-$87FF`) | `BANK2_GAME_TILE_SET_COPY_SIZE` (`$0800`) | 128 | Title init uses the game/base tile set in VRAM tile block 0. |
| `MainLoop` / `GAME_STATE_TITLE_INIT` | `TitleTileSet` `$6000-$6FFF` | `VRAM_TILE_BLOCK_8800` (`$8800-$97FF`) | `BANK2_TITLE_TILE_SET_COPY_SIZE` (`$1000`) | 256 | Title-specific tile set. |
| `MainLoop` / `GAME_STATE_PREPLAY_INIT` | `CommonTileSet` `$4800-$57FF` | `VRAM_TILE_BLOCK_8800` (`$8800-$97FF`) | `BANK2_COMMON_TILE_SET_COPY_SIZE` (`$1000`) | 256 | Initial copy for the pre-play/settings screen. |
| `MainLoop` / `GAME_STATE_PREPLAY_INIT` | `PreplayMenuOverlayTiles` `$5800-$5FFF` | `VRAM_TILE_BLOCK_8800` (`$8800-$8FFF`) | `BANK2_PREPLAY_MENU_OVERLAY_COPY_SIZE` (`$0800`) | 128 | Overwrites the lower half of the previous destination range with pre-play/menu alphabet, option-label, and panel fragments; final `$9000-$97FF` still comes from `CommonTileSet + $0800`. |
| `LoadGameTiles` | `CommonTileSet` `$4800-$57FF` | `VRAM_TILE_BLOCK_8800` (`$8800-$97FF`) | `BANK2_COMMON_TILE_SET_COPY_SIZE` (`$1000`) | 256 | Main gameplay tile load. |
| `LoadGameTiles` | `GameTileSet` `$4000-$47FF` | `VRAM_TILE_BLOCK_8000` (`$8000-$87FF`) | `BANK2_GAME_TILE_SET_COPY_SIZE` (`$0800`) | 128 | Main gameplay base tiles. |
| `LoadGameTiles`, 2P only | `TwoPlayerSharedTiles` `$71D0-$73CF` | `TWO_PLAYER_SHARED_TILES_VRAM_DEST` (`$9500-$96FF`) | `BANK2_TWO_PLAYER_SHARED_TILES_COPY_SIZE` (`$0200`) | 32 | Loaded whenever `TWO_PLAYER_FLAG != 0`; rendered evidence is mostly 2P text/panel fragments. |
| `LoadGameTiles`, 2P and `LINK_ROLE != LINK_ROLE_MASTER` | `TwoPlayerNonMasterTiles` `$6F70-$71CF` | `TWO_PLAYER_NONMASTER_TILES_VRAM_DEST` (`$81C0-$841F`) | `BANK2_TWO_PLAYER_NONMASTER_TILES_COPY_SIZE` (`$0260`) | 38 | Skipped for the master role; rendered evidence is character/art fragments for the non-master 2P tile load. |

## Bank 2 Unloaded Tail

| Source | Size | Tiles | Notes |
|--------|------|-------|-------|
| `Bank2UnusedTailTileData` `$73D0-$7FFF` | `$0C30` | 195 | No confirmed `MemcopyCall` or pointer reference targets this Bank 2 tail. The rendered sheet is mostly noise/padding-like rather than coherent UI text or character art, so the label stays scoped to an unused tail range. |

## Bank 3 Loads

Bank 3 is one full graphics block, `Bank3GraphicsData`, with load-site labels
for the observed copy ranges. `Yoshi/yoshi.sym` keeps the load-site label at
`03:$4000` because the disassembler symbol table stores one label per address;
the source keeps `Bank3GraphicsData` as a manual alias. Some source ranges
intentionally overlap; the table below records the observed copies rather than
assigning final visual semantics.

| Code path | Source label/range in Bank 3 | Destination | Size | Tiles | Notes |
|-----------|------------------------------|-------------|------|-------|-------|
| `ProcessMatching` | `Bank3MatchingTilesTo9000` `$4000-$47FF` | `VRAM_TILE_BLOCK_9000` (`$9000-$97FF`) | `BANK3_MATCHING_TILE_BLOCK_COPY_SIZE` (`$0800`) | 128 | Match animation/result setup path after LCD off; the routine first clears the 18-row BG map VRAM area with `MATCHING_BG_CLEAR_TILE`. |
| `ProcessMatching` | `Bank3MatchingTilesTo8800` `$4800-$4FFF` | `VRAM_TILE_BLOCK_8800` (`$8800-$8FFF`) | `BANK3_MATCHING_TILE_BLOCK_COPY_SIZE` (`$0800`) | 128 | Contains large text fragments such as `CONGRATULATION`, `SCORE`, `LEVEL`, `LOW`, `HIGH`, `TIME`. |
| `ProcessMatching` | `Bank3MatchingTilesTo8000` `$4E40-$563F` | `VRAM_TILE_BLOCK_8000` (`$8000-$87FF`) | `BANK3_MATCHING_TILE_BLOCK_COPY_SIZE` (`$0800`) | 128 | Overlaps the `$4800-$4FFF` source range and contains enemy/egg/result fragments. |
| `SetupResultRecordScreen` | `Bank3ResultRecordTilesTo9000` `$5400-$5BFF` | `VRAM_TILE_BLOCK_9000` (`$9000-$97FF`) | `BANK3_RESULT_RECORD_TILE_BLOCK_COPY_SIZE` (`$0800`) | 128 | Result-record font/text fragments including `RECORD`, `EGGS`, `A TYPE`, `B SCORE`. |
| `SetupResultRecordScreen` | `Bank3ResultRecordTilesTo8800` `$5C00-$63FF` | `VRAM_TILE_BLOCK_8800` (`$8800-$8FFF`) | `BANK3_RESULT_RECORD_TILE_BLOCK_COPY_SIZE` (`$0800`) | 128 | Result-record/high-score text fragments including `HI SCORE`, `MARIO`, `LUIGI`, `NEXT`. |
| `UpdateLinkResultMarksAndScreen` path | `Bank3LinkResultTilesTo9000` `$5DD0-$65CF` | `VRAM_TILE_BLOCK_9000` (`$9000-$97FF`) | `BANK3_LINK_RESULT_TILE_BLOCK_COPY_SIZE` (`$0800`) | 128 | Link-result name/text/number fragments; rendered evidence includes `MARIO`, `LUIGI`, `GOOD!`, and `VIEW`-like text fragments. |
| `UpdateLinkResultMarksAndScreen` path | `Bank3LinkResultTilesTo8800` `$65D0-$6DCF` | `VRAM_TILE_BLOCK_8800` (`$8800-$8FFF`) | `BANK3_LINK_RESULT_TILE_BLOCK_COPY_SIZE` (`$0800`) | 128 | Character, egg, and border fragments for the link-result screen. |
| `UpdateLinkResultMarksAndScreen`, when `STATE_TRANSITION != 0` | `Bank3LinkResultOverlayTilesTo9470` `$6AB0-$6E3F` | `LINK_RESULT_OVERLAY_VRAM_DEST` (`$9470-$97FF`) | `BANK3_LINK_RESULT_OVERLAY_9470_COPY_SIZE` (`$0390`) | 57 | Conditional terminal link-result character/egg overlay range. |
| `UpdateLinkResultMarksAndScreen`, when `STATE_TRANSITION != 0` | `Bank3LinkResultOverlayTilesTo8800` `$6E40-$757F` | `VRAM_TILE_BLOCK_8800` (`$8800-$8F3F`) | `BANK3_LINK_RESULT_OVERLAY_8800_COPY_SIZE` (`$0740`) | 116 | Conditional terminal link-result character/egg overlay range with repeated fragments. |

## ROM0 Queued Graphics

These copies come from Bank 0 data and are scheduled through `VRAMCopySetup`.
`VRAMCopyDMA` then transfers them during VBlank in 16-byte blocks.

| Code path | Source | Destination | Blocks | Bytes | Notes |
|-----------|--------|-------------|--------|-------|-------|
| A-type round-complete summary | `RoundCompleteSummaryGraphicTileData` `$3839-$3D38` | `ROUND_COMPLETE_SUMMARY_GRAPHIC_TILES_VRAM_DEST` (`$8820-$8D1F`) | `ROUND_COMPLETE_SUMMARY_GRAPHIC_TILES_COPY_BLOCKS` (`$50`) | `$0500` | 80 tiles copied from fixed ROM0 for the summary/reveal graphics. |
| A-type round-complete summary | `RoundCompleteSummaryTextTileData` `$3D39-$3E48` | `ROUND_COMPLETE_SUMMARY_TEXT_TILES_VRAM_DEST` (`$9140-$924F`) | `ROUND_COMPLETE_SUMMARY_TEXT_TILES_COPY_BLOCKS` (`$11`) | `$0110` | 17 `ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE` records used by `VERY GOOD!`, `EXCELLENT!`, and `SUPER PLAYER`. |

## Screen-Level Tile Block Map

The current evidence maps every confirmed Bank 2/3 tile-block load to a screen
or state-family. This is a load-role map rather than a per-tile atlas; exact
individual tile semantics are still named only where code references or rendered
text make them clear.

| Screen / flow | Bank 2/3 tile blocks | Final observed VRAM role |
|---------------|----------------------|--------------------------|
| Title init (`GAME_STATE_TITLE_INIT`) | Bank 2 `GameTileSet`, `TitleTileSet` | Base game tiles at `$8000-$87FF`; title logo/menu/Yoshi/copyright tiles at `$8800-$97FF`. |
| Pre-play/settings init (`GAME_STATE_PREPLAY_INIT`) | Bank 2 `CommonTileSet`, `PreplayMenuOverlayTiles` | Common playfield/settings tiles fill `$8800-$97FF`; pre-play/menu overlay replaces `$8800-$8FFF`, leaving the upper common half at `$9000-$97FF`. |
| Gameplay setup (`LoadGameTiles`) | Bank 2 `CommonTileSet`, `GameTileSet`; 2P optionally `TwoPlayerSharedTiles` and `TwoPlayerNonMasterTiles` | Main gameplay base tiles at `$8000-$87FF`, common gameplay/HUD tiles at `$8800-$97FF`; 2P shared fragments patch `$9500-$96FF`; non-master role fragments patch `$81C0-$841F`. |
| Matching/result panel (`ProcessMatching`) | Bank 3 `Bank3MatchingTilesTo9000`, `Bank3MatchingTilesTo8800`, `Bank3MatchingTilesTo8000` | Matching/result animation screen tiles fill `$9000-$97FF`, `$8800-$8FFF`, and `$8000-$87FF`; rendered text includes `CONGRATULATION`, `SCORE`, `LEVEL`, `LOW`, `HIGH`, and `TIME`. |
| Result record/high-score (`SetupResultRecordScreen`) | Bank 3 `Bank3ResultRecordTilesTo9000`, `Bank3ResultRecordTilesTo8800` | Result-record and high-score text/art tiles fill `$9000-$97FF` and `$8800-$8FFF`; rendered text includes `RECORD`, `HI SCORE`, `MARIO`, `LUIGI`, and `NEXT`. |
| Link result (`UpdateLinkResultMarksAndScreen`) | Bank 3 `Bank3LinkResultTilesTo9000`, `Bank3LinkResultTilesTo8800` | Link-result name/text/number fragments fill `$9000-$97FF`; character, egg, and border fragments fill `$8800-$8FFF`. |
| Terminal link result overlay (`STATE_TRANSITION != 0`) | Bank 3 `Bank3LinkResultOverlayTilesTo9470`, `Bank3LinkResultOverlayTilesTo8800` | Conditional overlay patches `$9470-$97FF` and `$8800-$8F3F` with terminal link-result character/egg fragments. |

## Rendered Tile Sheets

`tools/render_gb_tiles.py` decodes the observed ranges directly from
`Yoshi/yoshi.gb` into PNG evidence sheets:

```bash
python3 tools/render_gb_tiles.py --preset yoshi-graphics
```

The generated sheets and manifest live under
`docs/source_recovery/tile_sheets/`. First visual pass:

- Bank 2 `GameTileSet` and `CommonTileSet` contain gameplay character,
  egg, number, score/level, option, and playfield UI fragments.
- Bank 2 `TitleTileSet` contains the large title logo, copyright line,
  Yoshi character art, and title menu text fragments.
- Bank 2 `PreplayMenuOverlayTiles` contains alphabet/option labels and pre-play
  menu fragments; `TwoPlayerSharedTiles` and `TwoPlayerNonMasterTiles` split the
  always-loaded 2P fragments from the non-master-only 2P fragments.
- Bank 2 `Bank2UnusedTailTileData` renders as noise/padding-like data and has
  no confirmed load path.
- Bank 3 ranges are strongly result/high-score/link-result oriented: rendered
  text includes `CONGRATULATION`, `SCORE`, `LEVEL`, `LOW`, `HIGH`, `TIME`,
  `RECORD`, `HI SCORE`, `MARIO`, `LUIGI`, `GOOD!`, `VIEW`, and `NEXT`.
- ROM0 queued tile data contains A-type round-complete summary/reveal graphics
  emitted as paired 8-byte four-row records, plus compact glyph-tile records
  that decode the three summary messages.

## Open Questions

- Exact per-tile semantics inside several Bank 3 screen ranges remain broader
  than the screen-level load map above; keep those names scoped to their copy
  destination until code or rendered-layout evidence proves narrower roles.
- `Bank0TailPaddingData` after `RoundCompleteSummaryTextTileData` is confirmed
  as unreferenced ROM0 tail data rather than a graphics load target; it is now
  structured as a 204-word `$0039` padding prefix plus a 31-byte suffix.
- The pre-play Bank 2 copy deliberately overlaps VRAM destinations; the final
  tile composition should be verified with a tile renderer.
