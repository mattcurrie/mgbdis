# Option and Active Game Variables

This document tracks the recovered meaning of the option/settings variables around
`$C6B1-$C6B8`.

## Variables

| Address | Constant | Confidence | Meaning | Evidence |
|---------|----------|------------|---------|----------|
| `$C6B1` | `MENU_CURSOR` | High | Current row in the settings/start-wait menu. | Incremented/decremented in `Run1PPreplayLoop`; range is 0-3. Used to select which option byte at `$C6B2-$C6B5` changes. |
| `$C6B2` | `OPTION_GAME_TYPE` | High | Selected game type, likely A/B type. | `InitGameState` copies it to `GAME_TYPE`; result/menu drawing branches on it. |
| `$C6B3` | `OPTION_LEVEL` | High | Selected starting level. | `InitGameState` copies it to `ACTIVE_LEVEL` and `PROGRESSION_LEVEL`; option drawing displays five level choices. |
| `$C6B4` | `OPTION_SPEED` | High | Selected drop speed. | `InitGameState` copies it to `ACTIVE_SPEED`; gameplay timing/display code halves or adjusts values when nonzero. |
| `$C6B5` | `OPTION_BGM` | High | Selected BGM option. | `ApplyGameSettings` maps values 0, 1, 2 to BGM commands and value 3 to stop/off. |
| `$C6B6` | `TWO_PLAYER_FLAG` | High | 1P/2P mode flag. | Title input toggles this value; many paths use it separately from `GAME_TYPE`. |
| `$C6B7` | `ACTIVE_LEVEL` | High | Active in-game level copied from options or link settings. | Used by level thresholds, difficulty/scoring setup, and high-score/result paths. |
| `$C6B8` | `ACTIVE_SPEED` | High | Active in-game drop speed copied from options or link settings. | Used by speed display, fall timing, and result text selection. |
| `$C671` | `GAME_TYPE` | High | Active A/B-style game type, not 1P/2P. | Set from `OPTION_GAME_TYPE` in 1P; forced to 1 in 2P. `TWO_PLAYER_FLAG` independently handles 1P/2P. |
| `$C6E2` | `PROGRESSION_LEVEL` | High | Internal level/difficulty that can advance beyond the displayed active level. | Initialized from `OPTION_LEVEL` or `LINK_2P_SELECTED_LEVEL`, incremented by `AdvanceATypeLevelDisplayDigits` / `AdvanceLevelDisplayDigits`, capped at `$13` for `LevelFallDelayTable`, and passed to `ProcessMatching` in the B-type continuation path. |
| `$C6BC` | `TITLE_PLAYER_MARKER_TIMER` | High | Title 1P/2P selection marker blink timer. | `DisplayNextPiece` decrements it and reloads `$0A` or `$D0` when toggling the marker tiles. |
| `$C6BE` | `TITLE_PLAYER_MARKER_PHASE` | High | Title 1P/2P selection marker blink phase. | `DisplayNextPiece` toggles it between `$00` and `$01` before drawing `DrawNextBottom` or `DrawNextTop`; both routines draw the two marker rows at row/column pairs `$0505` and `$0605` with two consecutive tiles per row. |
| `$C6C1` | `BGM_PREVIEW_TIMER` | Medium | Countdown touched during option/result BGM preview handling. | `ApplyGameSettings` sets it to `1` after starting a BGM preview sound; `TickBgmPreviewTimer` decrements it from Bank 1. |
| `$C6C2` | `BGM_PREVIEW_PERIOD` | Low | BGM preview period/initial-value candidate. | `ApplyGameSettings` stores BGM-specific values `$1B`, `$2A`, or `$0C`; current direct reads have not been found, so the exact role remains open. |

## Menu Mechanics

- The settings/start-wait menu uses `MENU_CURSOR` as an index into four option bytes starting at `OPTION_GAME_TYPE`.
- Right/left input increments or decrements the selected option byte.
- `OptionMaxValueTable` at `00:$1F4C` and `RoundEndOptionMaxValueTable` at `00:$2C60` both contain `$02, $05, $02, $04`.
- Those table values are exclusive increment stops for the four rows: game type allows `0-1`, level allows `0-4`, speed allows `0-1`, and BGM allows `0-3`.
- Changing `OPTION_BGM` calls `ApplyGameSettings`, which immediately applies the selected BGM.

## Option UI Data

- `DrawOptionTextLabels` draws `$FF`-terminated tile strings for `A GAME`, `B GAME`, `LEVEL`, `SPEED`, `BGM`, `LOW`, `HIGH`, and `OFF`.
- `DrawOptionMarkers` clears eight marker positions from `OptionMarkerPositions` to tile `$4A`, then writes tile `$9A` at the currently selected game type, speed, and BGM positions.
- `DrawTileTripletList` consumes row/column/tile triples ending in `$FF`; the option screen uses these tables for inactive cursor tiles `$71/$70` and highlighted cursor tiles `$76/$75`.

## Naming Correction

The previous `PLAYER_MODE` name/comment was misleading: `$C671` is not the 1P/2P selector. The dedicated 1P/2P selector is `TWO_PLAYER_FLAG` at `$C6B6`; `$C671` is now named `GAME_TYPE` because it selects two gameplay/layout/result behaviors consistent with A/B type.
