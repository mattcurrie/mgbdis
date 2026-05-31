# Egg Counter State

The recovered egg counter state lives at `$C6D2-$C6D5`.

| Address | Name | Evidence |
|---------|------|----------|
| `$C6D2` | `EGG_COUNT_UNUSED_BYTE` | Cleared with the counter by `StartNextRound`, `InitPlayfield`, `RunTitleMenu`, and `ClearEggCountDigitsAndUnusedByte`; no direct read has been confirmed. |
| `$C6D3` | `EGG_COUNT_ONES` | Incremented first by `IncrementEggCountAndRefreshDisplay`; drawn by `DrawPlayfieldEggCountDigits` as tile `EGG_COUNT_TILE_BASE + digit`. |
| `$C6D4` | `EGG_COUNT_TENS` | Incremented when ones wraps; drawn by `DrawPlayfieldEggCountDigits` as tile `EGG_COUNT_TILE_BASE + digit`. |
| `$C6D5` | `EGG_COUNT_HUNDREDS` | Incremented when tens wraps; copied into result/history records before tens and ones. |
| `$C6E8-$C6EA` | `EGG_TEXT_PULSE_FRAME` / `EGG_TEXT_PULSE_TIMER` / `EGG_TEXT_PULSE_STEPS` | Seeded by `StartEggTextPulse` when the ones digit wraps; `UpdateEggTextAnimation` counts down and alternates `DrawEggTextFrameByIndex` frame 1/2 with a `$28` frame delay. |
| `$C6F3-$C6F4` | `EGG_TEXT_ALT_ANIM_ACTIVE` / `EGG_TEXT_ALT_ANIM_PHASE` | `EnableEggTextAltAnimation` sets the active flag when the tens digit wraps; VBlank state checking calls `ToggleEggTextAltAnimation` while playing, toggling `DrawEggTextFrameByIndex` frames 1/2. |

`IncrementEggCountAndRefreshDisplay` treats `$C6D3-$C6D5` as a decimal three-digit counter.
Each digit rolls over at `EGG_COUNT_DIGIT_LIMIT` (`10`), and the counter
saturates at `999` through `EGG_COUNT_MAX_DIGIT`. Before building the A-type
round-complete summary, `ShowATypeRoundCompleteSummary` low-nibble-normalizes
the three digits with `EGG_COUNT_DIGIT_MASK`.

`DrawPlayfieldEggCountDigits` writes the ones and tens digits into the gameplay display at
`PLAYFIELD_EGG_COUNT_A_TYPE_COORD` or `PLAYFIELD_EGG_COUNT_B_TYPE_COORD`.
`DrawPlayfieldEggDisplay` first draws egg text frame 0 through
`DrawEggTextFrame0` at `PLAYFIELD_EGG_DISPLAY_A_TYPE_COORD` or
`PLAYFIELD_EGG_DISPLAY_B_TYPE_COORD`, then calls `DrawPlayfieldEggCountDigits`. Result setup
copies the digits in hundreds/tens/ones order into
`CURRENT_RESULT_DETAIL_DIGITS`, which is later compared with previous result
records.
`DrawEggDisplayAtPlayfieldCoord` is the shared playfield draw target after
`Select1PPlayfieldEggDisplayCoord` chooses the A/B-type packed coordinate.
`UseATypeEggCountCoord` and `DrawPlayfieldEggCountDigitsAtCoord` name the local branch
inside `DrawPlayfieldEggCountDigits` that selects the A/B-type tilemap coordinate before
rendering those two digits.

When the ones digit wraps, `StartEggTextPulse` starts a short `DrawEggTextFrameByIndex`
frame 1/2 pulse. When the tens digit wraps, `EnableEggTextAltAnimation` enables
the continuous frame 1/2 alternate path driven by the playing-state VBlank
check.
`UpdateEggTextAnimation` reloads `EGG_TEXT_PULSE_TIMER`, draws
`EGG_TEXT_FRAME_1` or `EGG_TEXT_FRAME_2` through `DrawEggTextPulseFrame2` /
the fall-through frame-1 path, and then `ToggleEggTextPulseFrame` flips
`EGG_TEXT_PULSE_FRAME` with `EGG_TEXT_FRAME_TOGGLE_MASK` for the next pulse
step.
`DrawEggTextFrameByIndex` is 1P-only: `ReturnFromEggTextFrameDrawIn2P` skips the draw in 2P,
then `UseEggTextFrame0` / `UseEggTextFrame1` / `UseEggTextFrame2` select one of
the three four-row text frames. The row data is now emitted with
`EGG_TEXT_TILE_ROW_2`, `EGG_TEXT_TILE_ROW_3`, and `EGG_TEXT_TILE_ROW_4`, with
frame tile-base constants and `EGG_TEXT_ROW_FILL_TILE` for the side-panel fill
tile.

`UnusedInlineEggTextFrame0Drawer` at `01:$45C6` is a coherent inline egg-text
tile drawer between `DrawEggTextFrame0` and `DrawEggTextFrameByIndex`, but the live
`DrawEggTextFrame0` wrapper jumps directly to `DrawEggTextFrameByIndex` and the fragment
has no confirmed static entry.
It now uses `EGG_TEXT_FRAME0_TILE_BASE` and inline row-delta constants for its
direct tile writes; the live `EggTextFrame0TileRows` and shared frame-2 rows
reuse the same base.

The Bank 1 symbol file uses the same recovered labels for the egg text
animation entry points: `StartEggTextPulse`, `UpdateEggTextAnimation`,
`ToggleEggTextAltAnimation`, and `EnableEggTextAltAnimation`.

`LEVEL_DISPLAY_TICK_COUNTER` at `$C6D1` is a separate 10-tick divider used by the
title level-display path before calling `AdvanceATypeLevelDisplayDigits`. The
title/preplay redraw writes the digits at `TITLE_LEVEL_PREVIEW_DIGITS_COORD`,
an alias of the A-type playfield level digit coordinate. The level-display
digits use `LEVEL_DISPLAY_DIGIT_LIMIT` and `LEVEL_DISPLAY_MAX_DIGIT` for the
same decimal rollover/saturation pattern.
