# Title Menu Loop

`GAME_STATE_TITLE_MENU` runs `RunTitleMenu` once per frame after `MainLoop`
waits for VBlank and reads joypad input.

`RunTitleMenu` is not a one-shot initializer. Each frame it clears title/result
scratch bytes, resets the egg counter and link send queue staging, then delegates
to the Bank 1 title handlers:

- `ProcessTitleInput` updates the 1P/2P selection. `PADB_UP`,
  `PADB_DOWN`, and `PADB_SELECT` change `TWO_PLAYER_FLAG`, and
  `DrawTitlePlayerSelectionMarker` redraws the label-row selection marker at
  `TITLE_LABEL_PLAYER_MARKER_COORD` / `TITLE_LABEL_YOSHI_MARKER_COORD`.
  The Up path decrements the mode byte and rejects
  `TITLE_PLAYER_MODE_UNDERFLOW_SENTINEL`, while the Down path rejects values
  at or beyond `TITLE_PLAYER_MODE_COUNT`.
- `ProcessOptionInput` handles Start and link negotiation. In 1P, Start clears
  `rSB` and enters `GAME_STATE_PREPLAY_INIT`. In 2P, the starter writes
  `TITLE_LINK_START_BYTE` and the idle peer exposes `TITLE_LINK_READY_BYTE`;
  receiving the start byte sets `LINK_ROLE_SLAVE`, while receiving the ready
  byte sets `LINK_ROLE_MASTER`, then both paths enter
  `GAME_STATE_PREPLAY_INIT`.

`TickTitlePlayerMarkerBlink` drives the visible title selection marker blink by
alternating `DrawTitlePlayerMarkerTop` and `DrawTitlePlayerMarkerBottom` through
`TITLE_PLAYER_MARKER_PHASE`, using `TITLE_PLAYER_MARKER_TOP_DURATION` and
`TITLE_PLAYER_MARKER_BOTTOM_DURATION` as the two phase timers.

`DrawStringToGrid` copies `DRAW_STRING_ROW_END`-terminated tile strings through
`CopyStringToGridLoop`, then `AdvanceStringGridRow` advances the destination by
one BG-map row. This contract is the reason many text-like data ranges are kept
as terminated rows rather than instruction bytes.

This is why the old `InitGameVars` label was misleading: the routine is the
steady title menu update loop for state `$01`, even though it also resets several
scratch bytes before polling input.

`ResetTitleState` also seeds two low-confidence write-only bytes:
`TITLE_PLAYER_MARKER_UNUSED_DELAY` with
`TITLE_PLAYER_MARKER_UNUSED_DELAY_INITIAL`, and
`TITLE_RESET_UNUSED_HRAM_FLAG` with `1`. No consumer has been confirmed in the
current Yoshi source.

## Title Tilemap Layout

`InitTitleUI` seeds the title screen by filling fixed rectangles in
`BG_MAP_SHADOW`. The recovered layout constants describe BG-map positions, not
unique state variables:

| Address | Constant | Evidence |
|---------|----------|----------|
| `$C4B1` | `TITLE_FRAME_TOP_RIGHT_CAP_TOP_LEFT` | One-row, two-tile cap filled with `TITLE_FRAME_TOP_RIGHT_CAP_TILE_BASE` (`$50`). |
| `$C4B5` | `TITLE_FRAME_INNER_TOP_LEFT` | Four-row, 16-tile inner frame filled with `TITLE_FRAME_INNER_TILE_BASE` (`$80`). |
| `$C4C5` | `TITLE_FRAME_RIGHT_STRIP_TOP_LEFT` | Four-row, two-tile right strip filled with `TITLE_FRAME_RIGHT_STRIP_TILE_BASE` (`$C0`). |
| `$C507` | `TITLE_MENU_PANEL_TOP_LEFT` | Ten-row, ten-tile title menu panel filled with `TITLE_MENU_PANEL_TILE_BASE` (`$D0`). |
| `$C510` | `TITLE_LEVEL_STRIP_TOP_LEFT` | One-row, seven-tile title level strip filled with `TITLE_LEVEL_STRIP_TILE_BASE` (`$70`). |
| `$C575` | `TITLE_BOTTOM_RIGHT_PANEL_TOP_LEFT` | Five-row, four-tile lower-right panel filled with `TITLE_BOTTOM_RIGHT_PANEL_TILE_BASE` (`$34`). |
| `$0F06/$1006` | `TITLE_LABEL_PLAYER_COORD` / `TITLE_LABEL_YOSHI_COORD` | Packed row/column coordinates for the two title label strings. `TitleLabelTextPlayer` / `TitleLabelTextYoshi` use `TITLE_LABEL_TEXT_ROW` with per-label prefix tiles, `TITLE_LABEL_TEXT_SEPARATOR_TILE`, and the shared six-tile suffix at `TITLE_LABEL_TEXT_SHARED_TILE_BASE`. |
| `$0F05/$1005` | `TITLE_LABEL_PLAYER_MARKER_COORD` / `TITLE_LABEL_YOSHI_MARKER_COORD` | Packed row/column coordinates for the small marker drawn beside the two title label rows; `TITLE_LABEL_MARKER_CLEAR_TILE` clears both rows before `TITLE_LABEL_MARKER_SELECTED_TILE` marks the active one. |

The title/preplay level tick path redraws its two level digits at the packed
`TITLE_LEVEL_PREVIEW_DIGITS_COORD` coordinate (`$0812`), which aliases the
same row 8 / column 18 position used by the A-type playfield level HUD.
