# Falling Piece Timing

This note records the recovered timing pair that gates falling-piece updates.

## Variables

| Address | Constant | Evidence |
|---------|----------|----------|
| `$C696` | `PIECE_FALL_TIMER` | `UpdatePieceFallTimer` decrements it and `ReloadPieceFallTimer` copies in `PIECE_FALL_DELAY`; when drop/cursor animation is active at expiry, it stores `PIECE_FALL_TIMER_ANIM_HOLD_RELOAD` instead; `UpdateFallingPieceMotionAndLanding` returns without moving the staged object while it is nonzero; `HandlePlayfieldInput` / `ClampFastFallTimers` clamp it to at most `PIECE_FAST_FALL_TIMER_CLAMP` (`3`) while Down is held and active piece slots are already in update phase. |
| `$C6A7` | `PIECE_FALL_DELAY` | Setup paths load it from either `GetLevelFallDelay` or `GAME_TURN_DELAY`; `GetLevelFallDelay` caps `PROGRESSION_LEVEL` at `LEVEL_FALL_DELAY_MAX_INDEX` before `ReadLevelFallDelayTable` indexes the `LEVEL_FALL_DELAY_TABLE_COUNT` entries in `LevelFallDelayTable`; `UpdatePieceFallTimer` copies it into `PIECE_FALL_TIMER` when the timer is zero; `UpdateFallAcceleration` periodically decrements it down to `PIECE_FALL_DELAY_MIN`. |
| `$C6B0` | `PIECE_FALL_ACCEL_TIMER` | `InitBTypeFallTimingAndBoardSeed` initializes it, and `UpdateFallAcceleration` decrements it each update, reloads it through the low/high-level reload branches, then lowers `PIECE_FALL_DELAY` until the minimum delay is reached. |

## Flow

- `InitBTypeFallTimingAndBoardSeed` computes the initial delay from
  `LevelFallDelayTable` via `GetLevelFallDelay`, using `PROGRESSION_LEVEL` as
  the capped table index at `ReadLevelFallDelayTable` and halving the value
  when `ACTIVE_SPEED` is nonzero.
  The table entries are emitted as `LEVEL_FALL_DELAY_ENTRY
  LEVEL_FALL_DELAY_INDEX_0..19`, matching the capped `PROGRESSION_LEVEL` index
  rather than the on-screen displayed level.
- `InitGameTurnPieceDisplay` and `UpdateGameTurnPieceDisplay` copy the current
  `GAME_TURN_DELAY` into both `PIECE_FALL_DELAY` and `PIECE_FALL_TIMER`;
  `StoreInitialGameTurnPieceDelay` performs the initial write, while
  `StoreGameTurnPieceDelay` updates the per-record delay inside `LoadGameTurnPieceDisplayStep`.
  `GAME_TURN_PARAM_FALL_DELAY_OFFSET` is the third byte in each
  `GAME_TURN_PARAM_RECORD_SIZE` record.
  The table now uses the `GAME_TURN_PARAM` macro to emit the three
  consumed bytes plus the constant unread tail byte while preserving the
  `GameTurnParamTableContinuation` exact-address landmark with split-record
  macros around the crossing record.
  The two `PIECE_FALL_DELAY_MIN` clamp fragments immediately before the delay
  stores are still statically unreachable because both preceding branches jump
  directly to the store labels.
  The table index uses `GAME_TURN_TABLE_INDEX_SENTINEL` as a no-increment value
  and wraps `GAME_TURN_TABLE_LOOP_END_INDEX` back to
  `GAME_TURN_TABLE_LOOP_RESTART_INDEX`.
- `UpdatePieceFallTimer` is the main countdown owner. When `PIECE_FALL_TIMER`
  reaches zero, `ReloadPieceFallTimer` reloads it from `PIECE_FALL_DELAY`; while
  a drop or drop cursor animation is active, it keeps the timer at
  `PIECE_FALL_TIMER_ANIM_HOLD_RELOAD`.
- `UpdateFallingPieceMotionAndLanding` uses `PIECE_FALL_TIMER` as the movement gate. A nonzero
  timer returns `SPRITE_OBJECT_UPDATE_CONTINUE` without advancing
  `PIECE_FALL_POS` or the staged sprite object's Y position.
- `AdvanceFallingPiecePosition` increments `PIECE_FALL_POS`; while it remains
  below the selected column top row, the staged sprite object's base Y advances
  by `PIECE_FALL_SPRITE_Y_STEP` (`8` pixels) and the routine returns
  `SPRITE_OBJECT_UPDATE_CONTINUE`. At or past the selected row,
  `HandleFallingPieceReachedColumn` handles scan/landing behavior. A fall
  position at `BOARD_DRAW_FIRST_ROW` triggers
  `BuildGameOverPieceDisplayObjects` before the advance.
- `DrawLandedPieceAndUpdateColumnTop` is the direct placement path for a
  nonmatching or terminal-row landing. It plays `SND_PLACE_PIECE`, draws the
  staged payload into the selected column, and lowers that column's top row by
  two row units. If the stored top row becomes
  `COLUMN_TOP_ROW_OVERFLOW_SENTINEL`, the path sets `RESULT_GAME_OVER_FLAG` and
  enters `ProcessSinglePlayerGameOverResult` or queues
  `ROUND_RESULT_CODE_ZERO` for the 2P result flow.
- `CommitFallingPieceToBoard` is the matching/commit path. It plays
  `SND_COMMIT_PIECE`, adds `SCORE_DELTA_COMMIT_PIECE` (`00005` packed BCD),
  advances the selected column top row by two row units, clears the drawn
  falling position, and spawns the field-column effect object.
- `UpdateFallAcceleration` reloads `PIECE_FALL_ACCEL_TIMER` with
  `PIECE_FALL_ACCEL_PERIOD` (`$0A`) through
  `ReloadFallAccelTimerForLowLevel` / `ReloadFallAccelTimerForHighLevel`, then
  lowers `PIECE_FALL_DELAY` until it reaches `PIECE_FALL_DELAY_MIN` (`$02`).
  `UnreachableReloadFallAccelTimerForLevel3` matches the init-time level-3
  branch shape, but cannot currently be reached in `UpdateFallAcceleration`: the
  preceding `< PIECE_FALL_ACCEL_HIGH_LEVEL_THRESHOLD` branch already catches
  `PIECE_FALL_ACCEL_LEVEL3_VALUE` before the later level-3 comparison.
- When Down is held, `CheckFastFallActiveSlots` requires at least one gameplay
  object slot to be in update phase. `ClampFastFallTimers` then clamps
  `PIECE_FALL_TIMER`, and `ClampGameplayObjectFastFallLoop` applies the same
  clamp to each active gameplay object's
  `SPRITE_OBJECT_FAST_FALL_CLAMP_BYTE` (`+$0F`). No independent consumer has
  been confirmed for that slot-local byte.
- `InitBTypeFallTimingAndBoardSeed` uses `LoadUnhalvedBTypeFallDelay` or the
  active-speed halved path before `InitBTypeBoardSeed`; it then initializes
  `PIECE_FALL_ACCEL_TIMER` through the
  `PIECE_FALL_ACCEL_LEVEL3_VALUE` / `PIECE_FALL_ACCEL_HIGH_LEVEL_THRESHOLD`
  branch shape and `StoreInitialFallAccelTimer`.

The adjacent `$C697` byte is tracked separately as `PIECE_DISPLAY_REMAINING` in
`piece_display_state.md`.

## Open Landing/Scan Bytes

These bytes are close to the falling/display state block, but the current
evidence is not strong enough to assign semantic constants:

| Address | Current classification | Evidence |
|---------|------------------------|----------|
| `$C69D` | `UNRESOLVED_LANDING_RESET_BYTE_0` | `ClearRoundLandingAndResultState` clears it, and `HandleMatchedLandingScanState` clears it again when `UNRESOLVED_LANDING_SCAN_COUNTER` reaches zero. No direct or indirect consumer has been confirmed. |
| `$C6AE` | `UNRESOLVED_LANDING_RESET_BYTE_1` | Same write pattern as `$C69D`: cleared by `ClearRoundLandingAndResultState`, then cleared by `HandleMatchedLandingScanState` when `UNRESOLVED_LANDING_SCAN_COUNTER` reaches zero. No direct or indirect consumer has been confirmed. |
| `$C6BF` | `UNRESOLVED_LANDING_SCAN_COUNTER` | `ClearRoundLandingAndResultState` clears it. `RunBoardScanTriggerSequence` decrements it by one after `BoardScanAnimationStepLoop` / `RunBoardScanRoundTransition`; `HandleMatchedLandingScanState` decrements it by two when the staged tile/piece payload is `BOARD_SCAN_TARGET_PAYLOAD`, and clears the two landing reset bytes only when the result reaches zero. |
| `$C6C0` | `UNRESOLVED_LANDING_RESET_TIMER` | `ClearRoundLandingAndResultState` writes `UNRESOLVED_LANDING_RESET_TIMER_INITIAL` here, but no consumer has been confirmed in the current source. |

The `UNRESOLVED_LANDING_SCAN_COUNTER` read/write behavior is real, but its unit
is still unclear. A follow-up all-source and recent-history search found no
hidden producer for `$C69D/$C6AE/$C6BF/$C6C0`; `$C6BF` is still only cleared and
then decremented by scan/landing paths. Keep the `UNRESOLVED_` prefix until the
producer/consumer relationship is better proven.
