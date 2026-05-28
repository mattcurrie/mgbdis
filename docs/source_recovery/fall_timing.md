# Falling Piece Timing

This note records the recovered timing pair that gates falling-piece updates.

## Variables

| Address | Constant | Evidence |
|---------|----------|----------|
| `$C696` | `PIECE_FALL_TIMER` | `DisplayScore` decrements it and reloads it from `PIECE_FALL_DELAY`; `UpdateMatchState` returns without moving the staged object while it is nonzero; `CheckMatch` clamps it to at most 3 when active piece slots are already in update phase. |
| `$C6A7` | `PIECE_FALL_DELAY` | Setup paths load it from either `ProcessFalling` or `GAME_TURN_DELAY`; `ProcessFalling` indexes `LevelFallDelayTable` with `PROGRESSION_LEVEL` capped at `$13`; `DisplayScore` copies it into `PIECE_FALL_TIMER` when the timer is zero; `DisplaySpeed` periodically decrements it down to `PIECE_FALL_DELAY_MIN`. |
| `$C6B0` | `PIECE_FALL_ACCEL_TIMER` | `ValidatePosition` initializes it, and `DisplaySpeed` decrements it each update, reloads it with `PIECE_FALL_ACCEL_PERIOD`, then lowers `PIECE_FALL_DELAY` until the minimum delay is reached. |

## Flow

- `ValidatePosition` computes the initial delay from `LevelFallDelayTable` via
  `ProcessFalling`, using `PROGRESSION_LEVEL` as the capped table index and
  halving the value when `ACTIVE_SPEED` is nonzero.
- `DrawMenuCursor` and `UpdateMenuCursor` copy the current
  `GAME_TURN_DELAY` into both `PIECE_FALL_DELAY` and `PIECE_FALL_TIMER`.
- `DisplayScore` is the main countdown owner. When `PIECE_FALL_TIMER` reaches
  zero, it reloads the timer from `PIECE_FALL_DELAY`; while a drop or drop
  cursor animation is active, it keeps the timer at 1.
- `UpdateMatchState` uses `PIECE_FALL_TIMER` as the movement gate. A nonzero
  timer returns active state without advancing `PIECE_FALL_POS` or the staged
  sprite object's Y position.
- `DisplaySpeed` reloads `PIECE_FALL_ACCEL_TIMER` with
  `PIECE_FALL_ACCEL_PERIOD` (`$0A`) and lowers `PIECE_FALL_DELAY` until it
  reaches `PIECE_FALL_DELAY_MIN` (`$02`).

The adjacent `$C697` byte is tracked separately as `PIECE_DISPLAY_REMAINING` in
`piece_display_state.md`.
