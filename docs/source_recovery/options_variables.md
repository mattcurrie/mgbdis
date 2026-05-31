# Option and Active Game Variables

This document tracks the recovered meaning of the option/settings variables around
`$C6B1-$C6B8`.

## Variables

| Address | Constant | Confidence | Meaning | Evidence |
|---------|----------|------------|---------|----------|
| `$C6B1` | `MENU_CURSOR` | High | Current row in the settings/start-wait menu. | Incremented/decremented in `Run1PPreplayLoop`; range is `MENU_CURSOR_ROW_GAME_TYPE` through `MENU_CURSOR_ROW_BGM`. Used to select which option byte at `$C6B2-$C6B5` changes. |
| `$C6B2` | `OPTION_GAME_TYPE` | High | Selected game type, likely A/B type. | `InitGameState` copies it to `GAME_TYPE`; result/menu drawing branches on it. |
| `$C6B3` | `OPTION_LEVEL` | High | Selected starting level. | `InitGameState` copies it to `ACTIVE_LEVEL` and `PROGRESSION_LEVEL`; option drawing displays five level choices. |
| `$C6B4` | `OPTION_SPEED` | High | Selected drop speed. | `InitGameState` copies it to `ACTIVE_SPEED`; gameplay timing/display code halves or adjusts values when nonzero. |
| `$C6B5` | `OPTION_BGM` | High | Selected BGM option. | `ApplyGameSettings` maps values 0, 1, 2 to BGM commands and `OPTION_BGM_OFF_VALUE` to stop/off. |
| `$C6B6` | `TWO_PLAYER_FLAG` | High | 1P/2P mode flag. | Title input toggles this value; many paths use it separately from `GAME_TYPE`. |
| `$C6B7` | `ACTIVE_LEVEL` | High | Active in-game level copied from options or link settings. | Used by level thresholds, difficulty/scoring setup, and result/rank paths. |
| `$C6B8` | `ACTIVE_SPEED` | High | Active in-game drop speed copied from options or link settings. | Used by speed display, fall timing, and result text selection. |
| `$C671` | `GAME_TYPE` | High | Active A/B-style game type, not 1P/2P. | Set from `OPTION_GAME_TYPE` in 1P; forced to `GAME_TYPE_B` in 2P. `TWO_PLAYER_FLAG` independently handles 1P/2P. `GAME_TYPE_A` is `0`, and `GAME_TYPE_B` is `1`. |
| `$C6E2` | `PROGRESSION_LEVEL` | High | Internal level/difficulty that can advance beyond the displayed active level. | Initialized from `OPTION_LEVEL` or `LINK_2P_SELECTED_LEVEL`, incremented by `AdvanceATypeLevelDisplayDigits` / `AdvanceLevelDisplayDigits`, capped at `$13` for `LevelFallDelayTable`, and passed to `ProcessMatching` in the B-type continuation path. |
| `$C6BC` | `TITLE_PLAYER_MARKER_TIMER` | High | Title 1P/2P selection marker blink timer. | `TickTitlePlayerMarkerBlink` decrements it and reloads `$0A` or `$D0` when toggling the marker tiles. |
| `$C6BE` | `TITLE_PLAYER_MARKER_PHASE` | High | Title 1P/2P selection marker blink phase. | `TickTitlePlayerMarkerBlink` toggles it between `$00` and `$01` before drawing `DrawTitlePlayerMarkerBottom` or `DrawTitlePlayerMarkerTop`; both routines draw the two marker rows at row/column pairs `$0505` and `$0605` with two consecutive tiles per row. |
| `$C6C1` | `BGM_PREVIEW_TIMER` | Medium | Countdown touched during option/result BGM preview handling. | `ApplyGameSettings` sets it to `BGM_PREVIEW_TIMER_INITIAL` after starting a BGM preview sound; `ResetSettings` seeds it with `BGM_PREVIEW_RESET_VALUE`, and `TickBgmPreviewTimer` decrements it from Bank 1. |
| `$C6C2` | `BGM_PREVIEW_UNUSED_PERIOD` | Low | Write-only BGM preview period/initial-value candidate. | `ApplyGameSettings` stores `BGM_PREVIEW_UNUSED_PERIOD_OPTION0..2`, and `ResetSettings` mirrors `BGM_PREVIEW_RESET_VALUE` here. No direct read has been found in the current source. |

## Menu Mechanics

- The settings/start-wait menu uses `MENU_CURSOR` as an index into four option
  bytes starting at `OPTION_GAME_TYPE`. The row constants are
  `MENU_CURSOR_ROW_GAME_TYPE`, `MENU_CURSOR_ROW_LEVEL`,
  `MENU_CURSOR_ROW_SPEED`, and `MENU_CURSOR_ROW_BGM`; the detached wraparound
  path uses `MENU_CURSOR_ROW_COUNT` and `MENU_CURSOR_UNDERFLOW_SENTINEL`.
- Right/left input increments or decrements the selected option byte. The
  detached and live 1P pre-play input paths now use the hardware `PADB_UP`,
  `PADB_DOWN`, `PADB_RIGHT`, and `PADB_LEFT` bit constants rather than raw
  normalized joypad bit numbers.
- `DetachedPreplayOptionCountTable` at `00:$1F4C` and
  `PreplayLoopOptionCountTable` at `00:$2C60` both emit the four
  `PREPLAY_OPTION_COUNT_ENTRY` records: `OPTION_GAME_TYPE_OPTION_COUNT`,
  `OPTION_LEVEL_OPTION_COUNT`, `OPTION_SPEED_OPTION_COUNT`, and
  `OPTION_BGM_OPTION_COUNT`.
- Those table values are exclusive increment stops for the four rows: game type
  allows `0-1`, level allows `0-4`, speed allows `0-1`, and BGM allows `0-3`.
- Changing `OPTION_BGM` calls `ApplyGameSettings`, which immediately applies
  the selected BGM. In 1P, `ApplySinglePlayerSettings` maps BGM value 0 and
  `OPTION_BGM_VALUE_1` / `OPTION_BGM_VALUE_2` through
  `CheckBgmOption1Settings` / `CheckBgmOption2Settings` to the preview sounds,
  while `OPTION_BGM_OFF_VALUE` falls through to `ApplyBgmOffSettings`.

## Option UI Data

- `DrawOptionTextLabels` draws `DRAW_STRING_ROW_END`-terminated tile strings for `A GAME`, `B GAME`, `LEVEL`, `SPEED`, `BGM`, `LOW`, `HIGH`, and `OFF`; the `OptionText*` source rows now use `OPTION_TEXT_ROW_N` records with `OPTION_TEXT_TILE_*` constants.
- `Draw1PPreplayBackground` first fills the full 20x18 screen from row 0,
  column 0 with `PREPLAY_1P_BACKGROUND_TILE`, then clears the game-type,
  level, speed, and BGM option panels with `PREPLAY_1P_PANEL_CLEAR_TILE`.
- The 1P pre-play label/text helpers now name the game-type, level, speed, and
  BGM coordinates. The level and speed labels reuse the shared
  `PREPLAY_LEVEL_LABEL_*` and `PREPLAY_SPEED_LABEL_*` tile rows that the 2P
  setup screen also uses; `PREPLAY_LABEL_TILE_ROW_WIDTH` names the shared
  four-tile label width used when calling `DrawSequentialTileRowByCoord`.
  Game-type and BGM remain 1P-specific.
- The 1P BGM marker strings use `OPTION_MARKER_SELECTED_TILE` and
  `OPTION_MARKER_BLANK_TILE`, matching the option marker tiles used by the
  detached option screen.
- `DrawOptionDecorationTilesLoop` writes the five evenly spaced decoration
  tiles after the option text labels, starting from
  `OPTION_DECORATION_START_COORD` and stepping by
  `OPTION_DECORATION_COLUMN_STEP` columns.
- `DrawOptionMarkers` clears eight marker positions from `OptionMarkerPositions`
  to `OPTION_MARKER_BLANK_TILE` in `ClearOptionMarkerPositionsLoop`, then
  writes `OPTION_MARKER_SELECTED_TILE` at the currently selected game type,
  speed, and BGM positions. The table now uses `OPTION_MARKER_POSITION`
  records derived from the same `OPTION_MARKER_*_COORD` constants used by the
  selected-marker draw paths.
- `DrawTileTripletList` consumes row/column/tile triples ending in `$FF`; the
  option screen uses `DRAW_TILE_TRIPLET` records in
  `OptionCursorInactiveTileTriplets` for inactive cursor tiles and
  `OptionCursor*HighlightTileTriplets` for highlighted cursor rows.
- `DrawLevelCursorHighlight`, `DrawSpeedCursorHighlight`, and
  `DrawBgmCursorHighlight` select the highlighted cursor-row triplet list after
  `UpdateCursorDisplay` redraws the neutral option UI.
- `DrawOptionBoxLayout` draws the neutral option boxes, and
  `DrawOptionLevelValueBoxes` redraws the five neutral level-value boxes before
  the selected level value is highlighted.
- The option box redraw helpers now use `OPTION_BOX_NEUTRAL_TILE_OFFSET` for
  the base frame tiles and `OPTION_BOX_SELECTED_TILE_OFFSET` for the selected
  frame tiles. `UpdateCursorDisplay` compares the selected row against the
  `MENU_CURSOR_ROW_*` constants, and `DrawOptionValues` names the level value
  comparisons as `OPTION_LEVEL_VALUE_1..3`.
- `DrawOptionBoxAtCoord` uses named base frame tiles
  `OPTION_BOX_TOP_LEFT_TILE_BASE` through `OPTION_BOX_BOTTOM_RIGHT_TILE_BASE`.
  The individual option box helpers now name their row/column coordinates and
  inner row/width values with `OPTION_BOX_*_COORD` and
  `OPTION_BOX_*_INNER_SIZE`.
- The detached code immediately after `RunPreplayLoop` still contains a
  pre-play-like input handler, but current control flow jumps directly to
  `Run1PPreplayLoop` or `Run2PPreplayLoop`; its labels therefore use
  `DetachedPreplay` to avoid confusing it with the live 1P/2P loops. Its
  remaining label-tile fragment after `BgmMarkerNoneText` now uses the shared
  `PREPLAY_LEVEL_LABEL_*` tile-row constants and
  `PREPLAY_LABEL_TILE_ROW_WIDTH`.

## Naming Correction

The previous `PLAYER_MODE` name/comment was misleading: `$C671` is not the 1P/2P selector. The dedicated 1P/2P selector is `TWO_PLAYER_FLAG` at `$C6B6`; `$C671` is now named `GAME_TYPE` because it selects two gameplay/layout/result behaviors consistent with A/B type.
