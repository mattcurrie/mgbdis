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
| `MainLoop` / `GAME_STATE_TITLE_INIT` | `GameTileSet` `$4000-$47FF` | `$8000-$87FF` | `$0800` | 128 | Title init uses the game/base tile set in VRAM tile block 0. |
| `MainLoop` / `GAME_STATE_TITLE_INIT` | `TitleTileSet` `$6000-$6FFF` | `$8800-$97FF` | `$1000` | 256 | Title-specific tile set. |
| `MainLoop` / `GAME_STATE_PREPLAY_INIT` | `CommonTileSet` `$4800-$57FF` | `$8800-$97FF` | `$1000` | 256 | Initial copy for the pre-play/settings screen. |
| `MainLoop` / `GAME_STATE_PREPLAY_INIT` | `ExtraTiles` `$5800-$5FFF` | `$8800-$8FFF` | `$0800` | 128 | Overwrites the lower half of the previous destination range; final `$9000-$97FF` still comes from `CommonTileSet + $0800`. |
| `LoadGameTiles` | `CommonTileSet` `$4800-$57FF` | `$8800-$97FF` | `$1000` | 256 | Main gameplay tile load. |
| `LoadGameTiles` | `GameTileSet` `$4000-$47FF` | `$8000-$87FF` | `$0800` | 128 | Main gameplay base tiles. |
| `LoadGameTiles`, 2P only | `TwoPlayerTiles2` `$71D0-$73CF` | `$9500-$96FF` | `$0200` | 32 | Loaded whenever `TWO_PLAYER_FLAG != 0`. |
| `LoadGameTiles`, 2P and `LINK_ROLE != 1` | `TwoPlayerTiles1` `$6F70-$71CF` | `$81C0-$841F` | `$0260` | 38 | Skipped for link role `$01`. |

## Bank 3 Loads

Bank 3 is currently one labeled block, `TileGraphicsData2`, but the call sites
show several distinct source ranges. Some source ranges intentionally overlap;
the table below records the observed copies rather than assigning final visual
semantics.

| Code path | Source label/range in Bank 3 | Destination | Size | Tiles | Notes |
|-----------|------------------------------|-------------|------|-------|-------|
| `ProcessMatching` | `Bank3MatchingTilesTo9000` `$4000-$47FF` | `$9000-$97FF` | `$0800` | 128 | Match animation/result setup path after LCD off. |
| `ProcessMatching` | `Bank3MatchingTilesTo8800` `$4800-$4FFF` | `$8800-$8FFF` | `$0800` | 128 | Contains large text fragments such as `CONGRATULATION`, `SCORE`, `LEVEL`, `LOW`, `HIGH`, `TIME`. |
| `ProcessMatching` | `Bank3MatchingTilesTo8000` `$4E40-$563F` | `$8000-$87FF` | `$0800` | 128 | Overlaps the `$4800-$4FFF` source range and contains enemy/egg/result fragments. |
| `jr_000_29a0` result/round setup path | `Bank3ResultTilesTo9000` `$5400-$5BFF` | `$9000-$97FF` | `$0800` | 128 | Result font/text fragments including `RECORD`, `EGGS`, `A TYPE`, `B SCORE`. |
| `jr_000_29a0` result/round setup path | `Bank3ResultTilesTo8800` `$5C00-$63FF` | `$8800-$8FFF` | `$0800` | 128 | Result/high-score text fragments including `HI SCORE`, `MARIO`, `LUIGI`, `NEXT`. |
| `CheckHighScoreTable` path | `Bank3HighScoreTilesTo9000` `$5DD0-$65CF` | `$9000-$97FF` | `$0800` | 128 | High-score/result text and number tiles. |
| `CheckHighScoreTable` path | `Bank3HighScoreTilesTo8800` `$65D0-$6DCF` | `$8800-$8FFF` | `$0800` | 128 | Character and border fragments for high-score/result screens. |
| `CheckHighScoreTable`, when `STATE_TRANSITION != 0` | `Bank3HighScoreOverlayTilesTo9470` `$6AB0-$6E3F` | `$9470-$97FF` | `$0390` | 57 | Conditional character/overlay range. |
| `CheckHighScoreTable`, when `STATE_TRANSITION != 0` | `Bank3HighScoreOverlayTilesTo8800` `$6E40-$757F` | `$8800-$8F3F` | `$0740` | 116 | Conditional overlay/update range with repeated character fragments. |

## ROM0 Queued Graphics

These copies come from Bank 0 data and are scheduled through `VRAMCopySetup`.
`VRAMCopyDMA` then transfers them during VBlank in 16-byte blocks.

| Code path | Source | Destination | Blocks | Bytes | Notes |
|-----------|--------|-------------|--------|-------|-------|
| result/title setup near `ShowWinScreen` | `TitleResultTileData0` `$3839-$3D38` | `$8820-$8D1F` | `$50` | `$0500` | 80 tiles copied from fixed ROM0. |
| result/title setup near `ShowWinScreen` | `TitleResultTileData1` `$3D39-$3E48` | `$9140-$924F` | `$11` | `$0110` | 17 tiles copied from fixed ROM0. |

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
- Bank 2 `ExtraTiles` contains alphabet/option labels and pre-play menu
  fragments.
- Bank 3 ranges are strongly result/high-score oriented: rendered text
  includes `CONGRATULATION`, `SCORE`, `LEVEL`, `LOW`, `HIGH`, `TIME`,
  `RECORD`, `HI SCORE`, `MARIO`, `LUIGI`, and `NEXT`.
- ROM0 queued tile data contains compact result/count tiles and score
  value fragments, confirming that `00:$3839-$3E48` is graphics data.

## Open Questions

- Bank 3 source ranges still need visual decoding into concrete screen/tile
  roles.
- `Bank0TailGraphicsData` after `TitleResultTileData1` is confirmed as data,
  but its exact visual role is not yet named.
- The pre-play Bank 2 copy deliberately overlaps VRAM destinations; the final
  tile composition should be verified with a tile renderer.
