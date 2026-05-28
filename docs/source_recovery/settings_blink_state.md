# Settings Blink State

This note documents the recovered shared cursor blink state at `$C6F0-$C6F2`.

| Address | Name | Evidence |
|---------|------|----------|
| `$C6F0` | `LINK_SETTINGS_CURSOR` | Used only by the 2P pre-play settings loop. Up/down clamp it to `0` or `1`; left/right use it as an offset from `LINK_2P_SELECTED_LEVEL`, so row `0` edits level and row `1` edits speed. |
| `$C6F1` | `SETTINGS_BLINK_PHASE` | Toggled by `TickSettingsBlink` with `xor $01`. Drawing routines test the selected row plus this phase to substitute blank text for the active row. |
| `$C6F2` | `SETTINGS_BLINK_TIMER` | Set to `SETTINGS_BLINK_PERIOD` (`$0F`) on setup and input, decremented each frame by `TickSettingsBlink`, then reloaded when the blink phase flips. |

The same blink phase is shared by the 2P pre-play screen and the 1P
pre-play/settings screen:

- In the 2P pre-play path, `LINK_SETTINGS_CURSOR` selects the level or speed
  row. When `SETTINGS_BLINK_PHASE` is nonzero, `CalcBonus` and
  `DrawNextPieceSprite` draw the selected row as blank.
- In the 1P pre-play/settings path, `MENU_CURSOR` selects one of the four option
  rows. `ShowWinScreen`, `WaitForRestart`, `ProcessRestart`, and
  `UpdateContinue` use `SETTINGS_BLINK_PHASE` to blank the currently selected
  row's text or marker.
- Any accepted input clears `SETTINGS_BLINK_PHASE` and reloads
  `SETTINGS_BLINK_TIMER`, so the edited row is redrawn immediately before the
  next blink interval.
